#!/usr/bin/env bash
set -Eeuo pipefail

PROGRAM_NAME="NavoMTP"
PROGRAM_VERSION="1.0.0"
INSTALL_DIR="${NAVOMTP_INSTALL_DIR:-/opt/navomtp}"
COMPOSE_PROJECT="navomtp"
TELEMT_IMAGE_DEFAULT="ghcr.io/telemt/telemt:latest"
NGINX_IMAGE_DEFAULT="nginx:stable-alpine"
TELEMT_INTERNAL_PORT=9443
TELEMT_USER_DEFAULT="navo"

log() { printf '[%s] %s\n' "$PROGRAM_NAME" "$*"; }
warn() { printf '[%s] WARNING: %s\n' "$PROGRAM_NAME" "$*" >&2; }
die() { printf '[%s] ERROR: %s\n' "$PROGRAM_NAME" "$*" >&2; exit 1; }

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "请使用 root 运行：sudo bash navomtp.sh"
}

require_supported_host() {
  [[ -r /etc/os-release ]] || die "无法识别操作系统。首版仅支持 Debian/Ubuntu。"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    debian|ubuntu) ;;
    *) die "不支持的系统 ${ID:-unknown}。首版仅支持 Debian/Ubuntu。" ;;
  esac
  case "$(uname -m)" in
    x86_64|aarch64|arm64) ;;
    *) die "不支持的 CPU 架构：$(uname -m)（仅支持 amd64/arm64）。" ;;
  esac
  command -v systemctl >/dev/null 2>&1 || die "需要使用 systemd 的服务器。"
}

install_base_dependencies() {
  local missing=0 command_name
  for command_name in curl gpg openssl whiptail ss getent timeout; do
    command -v "$command_name" >/dev/null 2>&1 || missing=1
  done
  (( missing == 0 )) && return 0
  log "安装基础依赖（curl、GPG、OpenSSL、whiptail、DNS/网络工具）..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl gnupg openssl whiptail dnsutils iproute2 coreutils
}

configure_docker_repository() {
  # shellcheck disable=SC1091
  . /etc/os-release
  local distro="$ID" codename arch
  codename="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
  [[ -n "$codename" ]] || die "无法识别系统代号，不能安全配置 Docker 官方仓库。"
  arch="$(dpkg --print-architecture)"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${distro}/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
    "$arch" "$distro" "$codename" > /etc/apt/sources.list.d/docker.list
}

ensure_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    systemctl enable --now docker >/dev/null 2>&1 || die "Docker 已安装，但无法启动 docker.service。"
    docker info >/dev/null 2>&1 || die "Docker 命令存在，但守护进程不可用。"
    return 0
  fi

  if command -v docker >/dev/null 2>&1; then
    warn "检测到 Docker，但缺少 Compose 插件；将从 Docker 官方仓库补装插件，不会删除现有 Docker。"
  else
    log "未检测到 Docker，准备通过 Docker 官方 apt 仓库安装。"
  fi

  configure_docker_repository
  apt-get update
  if ! apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
    die "Docker 安装失败。脚本不会自动删除 docker.io、podman-docker 等冲突包，请先人工处理 apt 报告的冲突。"
  fi
  systemctl enable --now docker
  docker info >/dev/null 2>&1 || die "Docker 安装完成，但守护进程不可用。"
  docker compose version >/dev/null 2>&1 || die "Docker Compose 插件不可用。"
}

dialog_input() {
  local title="$1" prompt="$2" default_value="${3:-}" result
  result=$(whiptail --title "$title" --inputbox "$prompt" 10 76 "$default_value" 3>&1 1>&2 2>&3) || return 1
  printf '%s' "$result"
}

dialog_yesno() {
  whiptail --title "$1" --yesno "$2" 12 76
}

dialog_message() {
  whiptail --title "$1" --msgbox "$2" 20 78
}

generate_secret() {
  openssl rand -hex 16
}

lowercase() {
  LC_ALL=C tr '[:upper:]' '[:lower:]' <<< "$1"
}

validate_hex32() {
  [[ "$1" =~ ^[0-9A-Fa-f]{32}$ ]]
}

normalize_rate_mbps() {
  local value="$1"
  [[ "$value" =~ ^[0-9]{1,6}$ ]] || return 1
  value=$((10#$value))
  (( value <= 100000 )) || return 1
  printf '%s' "$value"
}

rate_limit_label() {
  if [[ "$1" == 0 ]]; then printf '不限速'; else printf '%s Mbps' "$1"; fi
}

load_rate_limits() {
  local upload download
  upload="$(state_value UPLOAD_LIMIT_MBPS 2>/dev/null || true)"
  download="$(state_value DOWNLOAD_LIMIT_MBPS 2>/dev/null || true)"
  UPLOAD_LIMIT_MBPS="$(normalize_rate_mbps "${upload:-0}")" || return 1
  DOWNLOAD_LIMIT_MBPS="$(normalize_rate_mbps "${download:-0}")" || return 1
}

# Legacy scalar values remain a read-compatible view of the first group.
group_value() {
  local field="$1" index="$2"
  if [[ -n "${GROUP_COUNT:-}" ]]; then
    case "$field" in
      USER) printf '%s' "${GROUP_USERS[$index]}" ;;
      SECRET) printf '%s' "${GROUP_SECRETS[$index]}" ;;
      TAG) printf '%s' "${GROUP_TAGS[$index]}" ;;
      UP) printf '%s' "${GROUP_UP[$index]}" ;;
      DOWN) printf '%s' "${GROUP_DOWN[$index]}" ;;
    esac
  else
    case "$field" in
      USER) printf '%s' "${TELEMT_USER:-navo}" ;;
      SECRET) printf '%s' "${TELEMT_SECRET:-}" ;;
      TAG) printf '%s' "${AD_TAG:-}" ;;
      UP) printf '%s' "${UPLOAD_LIMIT_MBPS:-0}" ;;
      DOWN) printf '%s' "${DOWNLOAD_LIMIT_MBPS:-0}" ;;
    esac
  fi
}

load_groups() {
  local count i key value
  count="$(state_value GROUP_COUNT 2>/dev/null || true)"
  GROUP_USERS=() GROUP_SECRETS=() GROUP_TAGS=() GROUP_UP=() GROUP_DOWN=()
  if [[ -z "$count" ]]; then
    GROUP_COUNT=1
    GROUP_USERS[0]="$(state_value TELEMT_USER 2>/dev/null || true)"
    GROUP_USERS[0]="${GROUP_USERS[0]:-navo}"
    GROUP_SECRETS[0]="$(state_value TELEMT_SECRET 2>/dev/null || true)"
    GROUP_TAGS[0]="$(state_value AD_TAG 2>/dev/null || true)"
    load_rate_limits || return 1
    GROUP_UP[0]="$UPLOAD_LIMIT_MBPS" GROUP_DOWN[0]="$DOWNLOAD_LIMIT_MBPS"
  else
    [[ "$count" =~ ^[1-9][0-9]{0,2}$ ]] && (( count <= 100 )) || return 1
    GROUP_COUNT="$count"
    for ((i=0; i<GROUP_COUNT; i++)); do
      key="GROUP_$((i+1))"
      GROUP_USERS[i]="$(state_value "${key}_USER")"
      GROUP_SECRETS[i]="$(state_value "${key}_SECRET")"
      GROUP_TAGS[i]="$(state_value "${key}_TAG")"
      value="$(state_value "${key}_UPLOAD_MBPS")"
      GROUP_UP[i]="$(normalize_rate_mbps "$value")" || return 1
      value="$(state_value "${key}_DOWNLOAD_MBPS")"
      GROUP_DOWN[i]="$(normalize_rate_mbps "$value")" || return 1
    done
  fi
  for ((i=0; i<GROUP_COUNT; i++)); do
    GROUP_SECRETS[i]="$(lowercase "${GROUP_SECRETS[$i]}")"
    GROUP_TAGS[i]="$(lowercase "${GROUP_TAGS[$i]}")"
  done
}

validate_groups() {
  local i user secret tag seen_users='|' seen_secrets='|'
  [[ "${GROUP_COUNT:-1}" =~ ^[1-9][0-9]{0,2}$ ]] && (( ${GROUP_COUNT:-1} <= 100 )) || return 1
  for ((i=0; i<${GROUP_COUNT:-1}; i++)); do
    user="$(group_value USER "$i")" secret="$(group_value SECRET "$i")" tag="$(group_value TAG "$i")"
    [[ "$user" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || return 1
    validate_hex32 "$secret" || return 1
    [[ -z "$tag" ]] || validate_hex32 "$tag" || return 1
    secret="$(lowercase "$secret")"
    [[ "$seen_users" != *"|$user|"* && "$seen_secrets" != *"|$secret|"* ]] || return 1
    seen_users+="$user|" seen_secrets+="$secret|"
    normalize_rate_mbps "$(group_value UP "$i")" >/dev/null || return 1
    normalize_rate_mbps "$(group_value DOWN "$i")" >/dev/null || return 1
  done
}

sync_first_group() {
  TELEMT_USER="${GROUP_USERS[0]}" TELEMT_SECRET="${GROUP_SECRETS[0]}" AD_TAG="${GROUP_TAGS[0]}"
  UPLOAD_LIMIT_MBPS="${GROUP_UP[0]}" DOWNLOAD_LIMIT_MBPS="${GROUP_DOWN[0]}"
}

group_summary() {
  local i tag
  for ((i=0; i<${GROUP_COUNT:-1}; i++)); do
    tag="$(group_value TAG "$i")"
    printf '组 %s | ad_tag：%s | 上行：%s | 下行：%s\n' "$((i+1))" \
      "${tag:-未设置}" \
      "$(rate_limit_label "$(group_value UP "$i")")" "$(rate_limit_label "$(group_value DOWN "$i")")"
  done
}

validate_ipv4() {
  local value="$1" part
  local -a octets
  IFS=. read -r -a octets <<< "$value"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  for part in "${octets[@]}"; do
    [[ "$part" =~ ^[0-9]{1,3}$ ]] || return 1
    (( 10#$part <= 255 )) || return 1
  done
}

validate_domain() {
  local domain label
  local -a labels
  domain="$(lowercase "$1")"
  [[ ${#domain} -le 253 && "$domain" == *.* ]] || return 1
  [[ "$domain" != *..* && "$domain" != .* && "$domain" != *. ]] || return 1
  IFS=. read -r -a labels <<< "$domain"
  for label in "${labels[@]}"; do
    [[ ${#label} -ge 1 && ${#label} -le 63 ]] || return 1
    [[ "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
  done
}

validate_public_host() {
  validate_ipv4 "$1" || validate_domain "$1"
}

normalize_ports() {
  local raw="${1//[[:space:]]/}" item
  local -a input output
  local seen=,
  [[ -n "$raw" ]] || return 1
  IFS=, read -r -a input <<< "$raw"
  for item in "${input[@]}"; do
    [[ "$item" =~ ^[0-9]{1,5}$ ]] || return 1
    (( 10#$item >= 1 && 10#$item <= 65535 )) || return 1
    [[ "$seen" != *",$((10#$item)),"* ]] || return 1
    item=$((10#$item))
    output+=("$item")
    seen+="$item,"
  done
  local joined
  IFS=, joined="${output[*]}"
  printf '%s' "$joined"
}

ports_to_array() {
  local ports="$1"
  IFS=, read -r -a PORT_ARRAY <<< "$ports"
}

state_value() {
  local key="$1" state_file="${2:-$INSTALL_DIR/state.env}"
  [[ -r "$state_file" ]] || return 1
  sed -n "s/^${key}=//p" "$state_file" | head -n 1
}

is_our_existing_port() {
  local port="$1" old_ports
  old_ports="$(state_value PUBLIC_PORTS 2>/dev/null || true)"
  [[ ",${old_ports}," == *",${port},"* ]] || return 1
  docker inspect navomtp-nginx >/dev/null 2>&1 || return 1
  docker port navomtp-nginx "${port}/tcp" >/dev/null 2>&1
}

check_ports_available() {
  local ports="$1" port
  ports_to_array "$ports"
  for port in "${PORT_ARRAY[@]}"; do
    if ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .; then
      is_our_existing_port "$port" || {
        warn "TCP 端口 $port 已被占用："
        ss -ltnp "sport = :$port" >&2 || true
        return 1
      }
    fi
  done
}

detect_public_ipv4() {
  curl -4fsS --connect-timeout 4 --max-time 8 https://api.ipify.org 2>/dev/null || true
}

probe_camouflage_domain() {
  local domain="$1"
  getent ahosts "$domain" >/dev/null 2>&1 || return 1
  timeout 10 openssl s_client -connect "${domain}:443" -servername "$domain" </dev/null >/dev/null 2>&1
}

select_network() {
  local existing candidate probe active_subnet candidates
  existing="$(state_value NETWORK_SUBNET 2>/dev/null || true)"
  if [[ -n "$existing" ]]; then
    active_subnet="$(docker network inspect navomtp-proxy-net --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || true)"
    if [[ -n "$active_subnet" ]]; then
      [[ "$active_subnet" == "$existing" ]] || die "现有 navomtp-proxy-net 网段与部署状态不一致。"
      printf '%s' "$existing"
      return 0
    fi
  fi
  candidates="${existing:+$existing }172.29.241.0/24 172.29.242.0/24 172.29.243.0/24 10.239.241.0/24 10.239.242.0/24"
  for candidate in $candidates; do
    probe="navomtp-probe-$$-${candidate//[.\/]/-}"
    if docker network create --driver bridge --subnet "$candidate" "$probe" >/dev/null 2>&1; then
      docker network rm "$probe" >/dev/null 2>&1 || true
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

network_ip() {
  local subnet="$1" host_octet="$2" prefix
  prefix="${subnet%.*}"
  printf '%s.%s' "$prefix" "$host_octet"
}

collect_configuration() {
  local default_host default_ports default_domain value normalized
  default_host="$(state_value PUBLIC_HOST 2>/dev/null || detect_public_ipv4)"
  default_ports="$(state_value PUBLIC_PORTS 2>/dev/null || printf '443')"
  default_domain="$(state_value TLS_DOMAIN 2>/dev/null || printf 'www.microsoft.com')"
  load_groups || { warn "保存的连接组配置无效，请检查 state.env。"; return 1; }

  while :; do
    value="$(dialog_input "公网地址" "填写连接链接中的服务器 IPv4 或域名：" "$default_host")" || return 1
    value="$(lowercase "$value")"
    if validate_public_host "$value"; then PUBLIC_HOST="$value"; break; fi
    dialog_message "输入错误" "公网地址必须是有效 IPv4 或 ASCII 域名。"
  done

  while :; do
    value="$(dialog_input "公网端口" "填写一个或多个 TCP 端口，使用英文逗号分隔：" "$default_ports")" || return 1
    if normalized="$(normalize_ports "$value")"; then
      if check_ports_available "$normalized"; then PUBLIC_PORTS="$normalized"; break; fi
      dialog_message "端口冲突" "至少一个端口已被其他服务占用。详情已输出到终端。"
    else
      dialog_message "输入错误" "端口必须在 1-65535 之间、不可重复，并使用英文逗号分隔。"
    fi
  done

  while :; do
    value="$(dialog_input "伪装域名" "填写 FakeTLS 伪装域名（不要包含 https:// 或路径）：" "$default_domain")" || return 1
    value="$(lowercase "$value")"
    if validate_domain "$value"; then TLS_DOMAIN="$value"; break; fi
    dialog_message "输入错误" "请输入有效的 ASCII 域名，例如 www.microsoft.com。"
  done

  local i j old_count="$GROUP_COUNT" duplicate direction current_rate rate_title candidate_counter
  while :; do
    value="$(dialog_input "连接组数量" "每组独立密钥、ad_tag 和限速，共用端口。填写 1–100；减少数量将删除末尾组：" "$GROUP_COUNT")" || return 1
    if [[ "$value" =~ ^[0-9]{1,3}$ ]] && (( 10#$value >= 1 && 10#$value <= 100 )); then
      normalized=$((10#$value))
      if (( normalized < old_count )); then
        dialog_yesno "删除连接组" "将删除第 $((normalized+1)) 至 $old_count 组，其旧连接链接将失效。确认继续？" || return 1
      fi
      GROUP_COUNT="$normalized"
      break
    fi
    dialog_message "输入错误" "连接组数量必须为 1–100。"
  done
  for ((i=0; i<GROUP_COUNT; i++)); do
    if [[ -z "${GROUP_USERS[$i]:-}" ]]; then
      candidate_counter=$((i+1))
      while :; do
        GROUP_USERS[i]="navo_$candidate_counter"
        duplicate=0
        for ((j=0; j<i; j++)); do [[ "${GROUP_USERS[$i]}" != "${GROUP_USERS[$j]}" ]] || duplicate=1; done
        (( duplicate == 1 )) || break
        candidate_counter=$((candidate_counter+1))
      done
    fi
    while :; do
      value="$(dialog_input "组 $((i+1))：访问密钥" "32 位十六进制；留空安全生成。每组密钥必须不同：" "${GROUP_SECRETS[$i]:-}")" || return 1
      [[ -n "$value" ]] || value="$(generate_secret)"
      duplicate=0
      if validate_hex32 "$value"; then
        value="$(lowercase "$value")"
        for ((j=0; j<i; j++)); do [[ "$value" != "${GROUP_SECRETS[$j]}" ]] || duplicate=1; done
        if (( duplicate == 0 )); then GROUP_SECRETS[i]="$value"; break; fi
      fi
      dialog_message "输入错误" "密钥必须是 32 位十六进制，且不能与前面的组重复。"
    done
    while :; do
      value="$(dialog_input "组 $((i+1))：广告标签" "填写该组 @MTProxybot 提供的 32 位十六进制 ad_tag；可留空：" "${GROUP_TAGS[$i]:-}")" || return 1
      if [[ -z "$value" ]] || validate_hex32 "$value"; then GROUP_TAGS[i]="$(lowercase "$value")"; break; fi
      dialog_message "输入错误" "ad_tag 必须留空或为 32 位十六进制。"
    done
    for direction in UP DOWN; do
      if [[ "$direction" == UP ]]; then
        current_rate="${GROUP_UP[$i]:-0}" rate_title="上行限速（客户端 → Telegram）"
      else
        current_rate="${GROUP_DOWN[$i]:-0}" rate_title="下行限速（Telegram → 客户端）"
      fi
    while :; do
      value="$(dialog_input "组 $((i+1))：$rate_title" "本组所有客户端及公开端口共享；整数 Mbps，0–100000，0 不限速：" "$current_rate")" || return 1
      if normalized="$(normalize_rate_mbps "$value")"; then
        if [[ "$direction" == UP ]]; then GROUP_UP[i]="$normalized"; else GROUP_DOWN[i]="$normalized"; fi
        break
      fi
      dialog_message "输入错误" "限速必须是 0–100000 的整数 Mbps，0 表示不限速。"
    done
    done
  done
  sync_first_group
  validate_groups || { warn "连接组配置无效。"; return 1; }

  if ! probe_camouflage_domain "$TLS_DOMAIN"; then
    dialog_yesno "域名探测失败" "无法确认 $TLS_DOMAIN 的 DNS 或 443/TLS 可达性。继续可能导致 FakeTLS 不可用。是否仍然继续？" || return 1
  fi

  TELEMT_IMAGE="$(state_value TELEMT_IMAGE 2>/dev/null || printf '%s' "$TELEMT_IMAGE_DEFAULT")"
  NGINX_IMAGE="$(state_value NGINX_IMAGE 2>/dev/null || printf '%s' "$NGINX_IMAGE_DEFAULT")"
  NETWORK_SUBNET="$(select_network)" || die "找不到可用的专用 Docker /24 网段。"
  NGINX_IP="$(network_ip "$NETWORK_SUBNET" 2)"
  TELEMT_IP="$(network_ip "$NETWORK_SUBNET" 3)"
}

render_telemt_config() {
  local destination="$1" first_port upload download i user tag
  validate_groups || return 1
  first_port="${PUBLIC_PORTS%%,*}"
  cat > "$destination" <<EOF
[general]
use_middle_proxy = true
log_level = "normal"

[general.modes]
classic = false
secure = false
tls = true

[general.links]
show = "*"
public_host = "${PUBLIC_HOST}"
public_port = ${first_port}

[server]
port = ${TELEMT_INTERNAL_PORT}
proxy_protocol = true
proxy_protocol_trusted_cidrs = ["${NGINX_IP}/32"]

[server.api]
enabled = false

[[server.listeners]]
ip = "0.0.0.0"

[censorship]
tls_domain = "${TLS_DOMAIN}"
mask = true
tls_emulation = true
tls_front_dir = "tlsfront"

[access.users]
EOF
  for ((i=0; i<${GROUP_COUNT:-1}; i++)); do
    printf '"%s" = "%s"\n' "$(group_value USER "$i")" "$(group_value SECRET "$i")" >> "$destination"
  done
  printf '\n[access.user_ad_tags]\n' >> "$destination"
  for ((i=0; i<${GROUP_COUNT:-1}; i++)); do
    tag="$(group_value TAG "$i")"
    [[ -z "$tag" ]] || printf '"%s" = "%s"\n' "$(group_value USER "$i")" "$tag" >> "$destination"
  done
  local rate_header=0
  for ((i=0; i<${GROUP_COUNT:-1}; i++)); do
    user="$(group_value USER "$i")"
    upload="$(normalize_rate_mbps "$(group_value UP "$i")")" || return 1
    download="$(normalize_rate_mbps "$(group_value DOWN "$i")")" || return 1
  if (( upload > 0 || download > 0 )); then
    if (( rate_header == 0 )); then printf '\n[access.user_rate_limits]\n' >> "$destination"; rate_header=1; fi
    printf '"%s" = { up_bps = %s, down_bps = %s }\n' \
      "$user" "$((upload * 1000000))" "$((download * 1000000))" >> "$destination"
  fi
  done
}

render_nginx_config() {
  local destination="$1" port
  ports_to_array "$PUBLIC_PORTS"
  {
    cat <<EOF
worker_processes auto;
error_log /dev/stderr notice;
pid /tmp/nginx.pid;

events {
    worker_connections 4096;
}

stream {
    log_format stream_log '\$remote_addr [\$time_local] SNI="\$ssl_preread_server_name" status=\$status bytes=\$bytes_sent/\$bytes_received session=\$session_time';
    access_log /dev/stdout stream_log;

    upstream telemt_backend {
        server ${TELEMT_IP}:${TELEMT_INTERNAL_PORT};
    }

    upstream reject_backend {
        server 127.0.0.1:1;
    }

    map \$ssl_preread_server_name \$backend {
        ${TLS_DOMAIN} telemt_backend;
        default reject_backend;
    }

    server {
EOF
    for port in "${PORT_ARRAY[@]}"; do
      printf '        listen %s reuseport;\n' "$port"
    done
    cat <<'EOF'
        ssl_preread on;
        preread_timeout 10s;
        proxy_connect_timeout 5s;
        proxy_timeout 1h;
        proxy_protocol on;
        proxy_pass $backend;
    }
}
EOF
  } > "$destination"
}

render_compose() {
  local destination="$1" port
  ports_to_array "$PUBLIC_PORTS"
  {
    cat <<EOF
name: ${COMPOSE_PROJECT}
services:
  telemt:
    image: ${TELEMT_IMAGE}
    container_name: navomtp-telemt
    restart: unless-stopped
    working_dir: /run/telemt
    command: ["/etc/telemt/config.toml"]
    volumes:
      - ./config/telemt.toml:/etc/telemt/config.toml:ro
    tmpfs:
      - /run/telemt:rw,mode=1777,size=4m
    read_only: true
    cap_drop: ["ALL"]
    security_opt:
      - no-new-privileges:true
    ulimits:
      nofile:
        soft: 65536
        hard: 262144
    healthcheck:
      test: ["CMD", "/app/telemt", "healthcheck", "/etc/telemt/config.toml", "--mode", "liveness"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 20s
    logging:
      driver: json-file
      options:
        max-size: "20m"
        max-file: "3"
    networks:
      proxy_net:
        ipv4_address: ${TELEMT_IP}

  nginx:
    image: ${NGINX_IMAGE}
    container_name: navomtp-nginx
    restart: unless-stopped
    depends_on:
      telemt:
        condition: service_healthy
    ports:
EOF
    for port in "${PORT_ARRAY[@]}"; do
      printf '      - "%s:%s/tcp"\n' "$port" "$port"
    done
    cat <<EOF
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    read_only: true
    tmpfs:
      - /var/cache/nginx:rw,size=16m
      - /var/run:rw,size=1m
      - /tmp:rw,size=1m
    cap_drop: ["ALL"]
    cap_add: ["NET_BIND_SERVICE", "CHOWN", "SETGID", "SETUID"]
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "nginx", "-t"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 5s
    logging:
      driver: json-file
      options:
        max-size: "20m"
        max-file: "3"
    networks:
      proxy_net:
        ipv4_address: ${NGINX_IP}

networks:
  proxy_net:
    name: navomtp-proxy-net
    driver: bridge
    ipam:
      config:
        - subnet: ${NETWORK_SUBNET}
EOF
  } > "$destination"
}

render_state() {
  local destination="$1" i
  cat > "$destination" <<EOF
PUBLIC_HOST=${PUBLIC_HOST}
PUBLIC_PORTS=${PUBLIC_PORTS}
TELEMT_USER=${TELEMT_USER}
TELEMT_SECRET=${TELEMT_SECRET}
AD_TAG=${AD_TAG}
TLS_DOMAIN=${TLS_DOMAIN}
UPLOAD_LIMIT_MBPS=${UPLOAD_LIMIT_MBPS:-0}
DOWNLOAD_LIMIT_MBPS=${DOWNLOAD_LIMIT_MBPS:-0}
NETWORK_SUBNET=${NETWORK_SUBNET}
NGINX_IP=${NGINX_IP}
TELEMT_IP=${TELEMT_IP}
TELEMT_IMAGE=${TELEMT_IMAGE}
NGINX_IMAGE=${NGINX_IMAGE}
EOF
  printf 'GROUP_COUNT=%s\n' "${GROUP_COUNT:-1}" >> "$destination"
  for ((i=0; i<${GROUP_COUNT:-1}; i++)); do
    printf 'GROUP_%s_USER=%s\nGROUP_%s_SECRET=%s\nGROUP_%s_TAG=%s\nGROUP_%s_UPLOAD_MBPS=%s\nGROUP_%s_DOWNLOAD_MBPS=%s\n' \
      "$((i+1))" "$(group_value USER "$i")" "$((i+1))" "$(group_value SECRET "$i")" \
      "$((i+1))" "$(group_value TAG "$i")" "$((i+1))" "$(group_value UP "$i")" \
      "$((i+1))" "$(group_value DOWN "$i")" >> "$destination"
  done
}

create_staging_tree() {
  local staging="$1"
  install -d -m 0700 "$staging/config" "$staging/nginx"
  render_telemt_config "$staging/config/telemt.toml" || return 1
  render_nginx_config "$staging/nginx/nginx.conf"
  render_compose "$staging/compose.yaml"
  render_state "$staging/state.env"
  chmod 0600 "$staging/config/telemt.toml" "$staging/state.env"
  chmod 0644 "$staging/nginx/nginx.conf" "$staging/compose.yaml"
}

telemt_config_check() {
  local config_file="$1"
  timeout 30 docker run --rm --user 0:0 --read-only --network none --tmpfs /run/telemt:rw,mode=1777,size=4m \
    -w /run/telemt -v "$config_file:/etc/telemt/config.toml:ro" \
    "$TELEMT_IMAGE" healthcheck /etc/telemt/config.toml --mode liveness
}

verify_rate_limit_support() {
  local staging="$1" probe_dir field result=0
  grep -q '^\[access.user_rate_limits\]' "$staging/config/telemt.toml" || return 0
  probe_dir="$(mktemp -d "$staging/rate-probe.XXXXXX")" || return 1
  # A lenient old parser may silently ignore new keys. It must reject a wrong
  # type for EACH direction, in addition to accepting the real candidate.
  for field in up_bps down_bps; do
    sed "s/${field} = [0-9][0-9]*/${field} = \"unsupported-probe\"/" \
      "$staging/config/telemt.toml" > "$probe_dir/config.toml"
    if telemt_config_check "$probe_dir/config.toml" > "$probe_dir/output" 2>&1; then
      result=1
    elif ! grep -Eq 'invalid type.*string|expected.*u64|expected.*integer' "$probe_dir/output"; then
      result=1
    fi
  done
  rm -rf -- "$probe_dir"
  if (( result != 0 )); then
    warn "无法确认当前 Telemt 镜像支持独立上下行限速。现有部署未替换，请先通过“更新镜像”升级后重试。"
    return 1
  fi
}

verify_ad_tag_support() {
  local staging="$1" probe_dir result=0
  # A bogus value must fail with a type error; ignored tables are unsafe.
  probe_dir="$(mktemp -d "$staging/tag-probe.XXXXXX")" || return 1
  sed '/^\[access.user_ad_tags\]/a\
"navomtp_type_probe" = 123
' "$staging/config/telemt.toml" > "$probe_dir/config.toml"
  if telemt_config_check "$probe_dir/config.toml" > "$probe_dir/output" 2>&1; then
    result=1
  elif ! grep -Eq 'invalid type.*integer|expected.*string' "$probe_dir/output"; then
    result=1
  fi
  rm -rf -- "$probe_dir"
  if (( result != 0 )); then
    warn "无法确认镜像支持每组 ad_tag；请通过“更新镜像”升级后重试。"
    return 1
  fi
}

verify_images_and_staging() {
  local staging="$1" nginx_build
  log "拉取并验证容器镜像..."
  docker pull "$TELEMT_IMAGE" || return 1
  docker pull "$NGINX_IMAGE" || return 1
  nginx_build="$(docker run --rm "$NGINX_IMAGE" nginx -V 2>&1)" || return 1
  if [[ "$nginx_build" != *"--with-stream"* || "$nginx_build" != *"--with-stream_ssl_preread_module"* ]]; then
    warn "所选 Nginx 镜像不包含 stream/ssl_preread 模块。"
    return 1
  fi
  docker compose --project-name "$COMPOSE_PROJECT" -f "$staging/compose.yaml" config --quiet || return 1
  docker run --rm -v "$staging/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" "$NGINX_IMAGE" nginx -t || return 1
  if ! telemt_config_check "$staging/config/telemt.toml"; then
    warn "Telemt 配置验证失败；若设置了限速，请通过“更新镜像”升级后重试。"
    return 1
  fi
  verify_rate_limit_support "$staging" || return 1
  verify_ad_tag_support "$staging"
}

backup_current() {
  local backup_dir="$1"
  [[ -f "$INSTALL_DIR/compose.yaml" ]] || return 0
  install -d -m 0700 "$backup_dir/config" "$backup_dir/nginx"
  cp -p "$INSTALL_DIR/compose.yaml" "$backup_dir/"
  [[ -f "$INSTALL_DIR/state.env" ]] && cp -p "$INSTALL_DIR/state.env" "$backup_dir/"
  [[ -f "$INSTALL_DIR/links.txt" ]] && cp -p "$INSTALL_DIR/links.txt" "$backup_dir/"
  cp -p "$INSTALL_DIR/config/telemt.toml" "$backup_dir/config/"
  cp -p "$INSTALL_DIR/nginx/nginx.conf" "$backup_dir/nginx/"
}

install_staging() {
  local staging="$1"
  install -d -m 0700 "$INSTALL_DIR/config" "$INSTALL_DIR/nginx" "$INSTALL_DIR/backups"
  install -m 0640 "$staging/config/telemt.toml" "$INSTALL_DIR/config/telemt.toml.new"
  install -m 0644 "$staging/nginx/nginx.conf" "$INSTALL_DIR/nginx/nginx.conf.new"
  install -m 0644 "$staging/compose.yaml" "$INSTALL_DIR/compose.yaml.new"
  install -m 0600 "$staging/state.env" "$INSTALL_DIR/state.env.new"
  chown 0:65532 "$INSTALL_DIR/config/telemt.toml.new"
  mv -f "$INSTALL_DIR/config/telemt.toml.new" "$INSTALL_DIR/config/telemt.toml"
  mv -f "$INSTALL_DIR/nginx/nginx.conf.new" "$INSTALL_DIR/nginx/nginx.conf"
  mv -f "$INSTALL_DIR/compose.yaml.new" "$INSTALL_DIR/compose.yaml"
  mv -f "$INSTALL_DIR/state.env.new" "$INSTALL_DIR/state.env"
}

restore_backup() {
  local backup_dir="$1"
  [[ -f "$backup_dir/compose.yaml" ]] || return 1
  cp -p "$backup_dir/compose.yaml" "$INSTALL_DIR/compose.yaml"
  cp -p "$backup_dir/state.env" "$INSTALL_DIR/state.env"
  cp -p "$backup_dir/config/telemt.toml" "$INSTALL_DIR/config/telemt.toml"
  cp -p "$backup_dir/nginx/nginx.conf" "$INSTALL_DIR/nginx/nginx.conf"
  [[ ! -f "$backup_dir/links.txt" ]] || cp -p "$backup_dir/links.txt" "$INSTALL_DIR/links.txt"
}

compose() {
  docker compose --project-name "$COMPOSE_PROJECT" --project-directory "$INSTALL_DIR" -f "$INSTALL_DIR/compose.yaml" "$@"
}

wait_for_healthy() {
  local deadline=$((SECONDS + 90)) telemt_health nginx_health
  while (( SECONDS < deadline )); do
    telemt_health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' navomtp-telemt 2>/dev/null || true)"
    nginx_health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' navomtp-nginx 2>/dev/null || true)"
    [[ "$telemt_health" == healthy && "$nginx_health" == healthy ]] && return 0
    [[ "$telemt_health" == unhealthy || "$nginx_health" == unhealthy ]] && return 1
    sleep 2
  done
  return 1
}

extract_base_link() {
  local deadline=$((SECONDS + 30)) link secret="${1:-}" domain_hex
  domain_hex="$(printf '%s' "$TLS_DOMAIN" | od -An -tx1 | tr -d ' \n')"
  while (( SECONDS < deadline )); do
    link="$(compose logs --no-color telemt 2>/dev/null | grep -Eo "tg://proxy\\?[^[:space:]\"']+" | \
      grep -E "[?&]secret=ee${secret}${domain_hex}(&|$)" | tail -n 1 || true)"
    if [[ -n "$link" ]]; then
      printf '%s' "$link"
      return 0
    fi
    sleep 2
  done
  return 1
}

write_links() {
  local base_link port tg_link https_link query i secret output
  output="$(mktemp "$INSTALL_DIR/links.XXXXXX")" || return 1
  chmod 0600 "$output"
  ports_to_array "$PUBLIC_PORTS"
  for ((i=0; i<${GROUP_COUNT:-1}; i++)); do
    secret="$(group_value SECRET "$i")"
    base_link="$(extract_base_link "$secret")" || {
      rm -f -- "$output" "$INSTALL_DIR/links.txt"
      warn "未取得组 $((i+1)) 的官方 FakeTLS 链接；请稍后通过「显示连接链接」重试。"
      return 0
    }
    printf '连接组 %s | ad_tag：%s\n' "$((i+1))" "$(group_value TAG "$i")" >> "$output"
  for port in "${PORT_ARRAY[@]}"; do
    tg_link="$(sed -E "s/([?&]port=)[0-9]+/\\1${port}/" <<< "$base_link")"
    query="${tg_link#*\?}"
    https_link="https://t.me/proxy?${query}"
    printf '端口 %s\n%s\n%s\n\n' "$port" "$tg_link" "$https_link" >> "$output"
  done
  done
  mv -f -- "$output" "$INSTALL_DIR/links.txt"
}

record_image_digests() {
  local telemt_digest nginx_digest
  telemt_digest="$(docker image inspect "$TELEMT_IMAGE" --format '{{index .RepoDigests 0}}' 2>/dev/null || true)"
  nginx_digest="$(docker image inspect "$NGINX_IMAGE" --format '{{index .RepoDigests 0}}' 2>/dev/null || true)"
  {
    printf 'TELEMT=%s\n' "$telemt_digest"
    printf 'NGINX=%s\n' "$nginx_digest"
    printf 'RECORDED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$INSTALL_DIR/image-digests.txt"
  chmod 0600 "$INSTALL_DIR/image-digests.txt"
}

maybe_configure_ufw() {
  local port
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null | grep -q '^Status: active' || return 0
  if dialog_yesno "UFW 防火墙" "检测到 UFW 已启用。是否放行 TCP 端口：${PUBLIC_PORTS}？\n\n脚本不会修改云厂商安全组。"; then
    ports_to_array "$PUBLIC_PORTS"
    for port in "${PORT_ARRAY[@]}"; do ufw allow "${port}/tcp"; done
  fi
}

deploy_configuration() {
  local staging backup_dir had_previous=0 timestamp
  staging="$(mktemp -d /tmp/navomtp-stage.XXXXXX)"
  create_staging_tree "$staging" || { rm -rf -- "$staging"; die "连接组配置无效，未修改现有部署。"; }
  if ! verify_images_and_staging "$staging"; then
    rm -rf -- "$staging"
    die "候选配置或容器镜像验证失败，未修改现有部署。"
  fi

  timestamp="$(date +%Y%m%d-%H%M%S)"
  backup_dir="$INSTALL_DIR/backups/$timestamp"
  if [[ -f "$INSTALL_DIR/compose.yaml" ]]; then
    had_previous=1
    backup_current "$backup_dir"
  fi
  install_staging "$staging"

  log "启动 NavoMTP 服务..."
  if ! compose up -d --force-recreate --remove-orphans || ! wait_for_healthy; then
    warn "新配置启动失败。"
    compose logs --no-color --tail 100 >&2 || true
    if (( had_previous == 1 )); then
      warn "正在恢复上一版配置。"
      restore_backup "$backup_dir"
      compose up -d --force-recreate --remove-orphans || true
      wait_for_healthy || warn "上一版配置也未恢复到健康状态，请立即检查日志。"
    else
      compose down --remove-orphans || true
    fi
    rm -rf -- "$staging"
    return 1
  fi

  write_links
  record_image_digests
  maybe_configure_ufw
  log "部署成功。请在云厂商安全组中放行 TCP：$PUBLIC_PORTS"
  show_links false
  rm -rf -- "$staging"
}

install_or_configure() {
  require_root
  require_supported_host
  install_base_dependencies
  ensure_docker
  collect_configuration || { log "已取消。"; return 0; }
  local summary
  summary="公网地址：$PUBLIC_HOST\n公网端口：$PUBLIC_PORTS\n伪装域名：$TLS_DOMAIN\n$(group_summary)\n每组独立限速，组内所有客户端及端口共享。\n\n仅启用 FakeTLS；错误或缺失 SNI 将被拒绝。"
  dialog_yesno "确认部署" "$summary" || { log "已取消。"; return 0; }
  deploy_configuration
}

require_installation() {
  [[ -f "$INSTALL_DIR/compose.yaml" && -f "$INSTALL_DIR/state.env" ]] || die "尚未安装 NavoMTP。"
}

load_state() {
  require_installation
  PUBLIC_HOST="$(state_value PUBLIC_HOST)"
  PUBLIC_PORTS="$(state_value PUBLIC_PORTS)"
  TELEMT_USER="$(state_value TELEMT_USER)"
  TELEMT_SECRET="$(state_value TELEMT_SECRET)"
  AD_TAG="$(state_value AD_TAG || true)"
  TLS_DOMAIN="$(state_value TLS_DOMAIN)"
  load_rate_limits || die "保存的限速值无效，请检查 state.env。"
  load_groups && validate_groups || die "保存的连接组配置无效，请检查 state.env。"
  sync_first_group
  NETWORK_SUBNET="$(state_value NETWORK_SUBNET)"
  NGINX_IP="$(state_value NGINX_IP)"
  TELEMT_IP="$(state_value TELEMT_IP)"
  TELEMT_IMAGE="$(state_value TELEMT_IMAGE)"
  NGINX_IMAGE="$(state_value NGINX_IMAGE)"
}

show_status() {
  require_root
  require_installation
  compose ps
  printf '\n镜像摘要：\n'
  [[ ! -f "$INSTALL_DIR/image-digests.txt" ]] || sed -n '1,3p' "$INSTALL_DIR/image-digests.txt"
  printf '\n公开 TCP 端口：%s\n' "$(state_value PUBLIC_PORTS)"
  load_groups && validate_groups || die "保存的连接组配置无效，请检查 state.env。"
  group_summary
  printf '每组独立限速；组内所有客户端及公开端口共享。\n'
  printf '云厂商安全组需单独确认。\n'
}

show_logs() {
  require_root
  require_installation
  compose logs --tail 200 -f
}

show_links() {
  local use_dialog="${1:-true}"
  require_root
  require_installation
  load_state
  [[ -s "$INSTALL_DIR/links.txt" ]] || write_links
  [[ -s "$INSTALL_DIR/links.txt" ]] || die "暂时无法取得 Telemt 官方生成链接，请检查日志后重试。"
  if [[ "$use_dialog" == true && -t 1 ]]; then
    whiptail --title "连接链接（敏感信息）" --scrolltext --msgbox "$(<"$INSTALL_DIR/links.txt")" 24 90
  else
    printf '\n连接链接（包含密钥，请勿公开）：\n\n'
    cat "$INSTALL_DIR/links.txt"
  fi
}

update_images() {
  require_root
  require_supported_host
  install_base_dependencies
  ensure_docker
  load_state
  dialog_yesno "更新镜像" "将拉取 Telemt 与 Nginx 新镜像并重建容器。失败时会恢复原镜像。是否继续？" || return 0
  local old_telemt_id old_nginx_id
  old_telemt_id="$(docker image inspect "$TELEMT_IMAGE" --format '{{.Id}}')"
  old_nginx_id="$(docker image inspect "$NGINX_IMAGE" --format '{{.Id}}')"
  if ! compose pull || ! verify_images_and_staging "$INSTALL_DIR" || \
    ! compose up -d --force-recreate --remove-orphans || ! wait_for_healthy; then
    warn "镜像更新失败，恢复更新前镜像。"
    docker tag "$old_telemt_id" "$TELEMT_IMAGE"
    docker tag "$old_nginx_id" "$NGINX_IMAGE"
    compose up -d --force-recreate --remove-orphans || true
    wait_for_healthy || warn "原镜像未恢复到健康状态，请立即检查日志。"
    return 1
  fi
  record_image_digests
  write_links
  log "镜像更新完成。"
}

uninstall_navomtp() {
  require_root
  require_installation
  dialog_yesno "卸载 NavoMTP" "将停止并删除 NavoMTP 容器、专用网络及 $INSTALL_DIR 中的配置和密钥。\n\nDocker 本身和镜像不会被删除。此操作不可撤销，是否继续？" || return 0
  compose down --remove-orphans || true
  [[ "$INSTALL_DIR" == /opt/navomtp || "$INSTALL_DIR" == /tmp/navomtp-test-* ]] || die "拒绝删除非预期目录：$INSTALL_DIR"
  rm -rf -- "$INSTALL_DIR"
  log "已删除 NavoMTP 部署；Docker 与容器镜像仍保留。"
}

show_help() {
  cat <<EOF
${PROGRAM_NAME} ${PROGRAM_VERSION}

用法：sudo bash navomtp.sh [命令]

命令：
  install      首次安装或重新配置
  configure    修改现有配置
  status       查看容器状态
  logs         持续查看最近日志
  update       拉取并切换新镜像
  links        显示 Telegram 连接链接
  uninstall    卸载本项目（不卸载 Docker）
  help         显示帮助

不带命令运行时进入中文终端菜单。
EOF
}

main_menu() {
  require_root
  require_supported_host
  install_base_dependencies
  local choice
  while :; do
    choice=$(whiptail --title "${PROGRAM_NAME} ${PROGRAM_VERSION}" --menu "请选择操作：" 20 76 10 \
      "1" "安装 / 修改配置" \
      "2" "查看运行状态" \
      "3" "查看实时日志" \
      "4" "更新容器镜像" \
      "5" "显示连接链接" \
      "6" "卸载 NavoMTP" \
      "0" "退出" 3>&1 1>&2 2>&3) || break
    case "$choice" in
      1) install_or_configure ;;
      2) show_status; read -r -p "按 Enter 返回菜单..." _ ;;
      3) show_logs || true ;;
      4) update_images ;;
      5) show_links ;;
      6) uninstall_navomtp; [[ -d "$INSTALL_DIR" ]] || break ;;
      0) break ;;
    esac
  done
}

main() {
  case "${1:-menu}" in
    menu) main_menu ;;
    install|configure) install_or_configure ;;
    status) show_status ;;
    logs) show_logs ;;
    update) update_images ;;
    links) show_links false ;;
    uninstall) uninstall_navomtp ;;
    help|-h|--help) show_help ;;
    *) show_help >&2; exit 2 ;;
  esac
}

if [[ "${NAVOMTP_LIB_ONLY:-0}" != 1 ]]; then
  main "$@"
fi
