#!/usr/bin/env bash
set -Eeuo pipefail

PROGRAM_NAME="NavoMTP"
PROGRAM_VERSION="1.0.0"
PROMOTION_TAG="4caf5a6f0d774c5a865b15fd0a678343"
INSTALL_DIR="${NAVOMTP_INSTALL_DIR:-/opt/navomtp}"
COMPOSE_PROJECT="navomtp"
TELEMT_IMAGE_DEFAULT="ghcr.io/telemt/telemt:latest"
NGINX_IMAGE_DEFAULT="nginx:stable-alpine"
TELEMT_INTERNAL_PORT=9443
TELEMT_USER_DEFAULT="navo"
TELEMT_CONFIG_PATH="/etc/telemt/telemt.toml"
SCRIPT_SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
SYSTEMD_DIR="${NAVOMTP_SYSTEMD_DIR:-/etc/systemd/system}"

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
  for command_name in curl gpg openssl whiptail ss getent timeout flock; do
    command -v "$command_name" >/dev/null 2>&1 || missing=1
  done
  (( missing == 0 )) && return 0
  log "安装基础依赖（curl、GPG、OpenSSL、whiptail、DNS/网络工具）..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl gnupg openssl whiptail dnsutils iproute2 coreutils util-linux
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

# Legacy secret/tag scalars remain a read-compatible view of the first group.
group_value() {
  local field="$1" index="$2"
  if [[ -n "${GROUP_COUNT:-}" ]]; then
    case "$field" in
      USER) printf '%s' "${GROUP_USERS[$index]}" ;;
      SECRET) printf '%s' "${GROUP_SECRETS[$index]}" ;;
      TAG) printf '%s' "${GROUP_TAGS[$index]}" ;;
    esac
  else
    case "$field" in
      USER) printf '%s' "${TELEMT_USER:-navo}" ;;
      SECRET) printf '%s' "${TELEMT_SECRET:-}" ;;
      TAG) printf '%s' "${AD_TAG:-}" ;;
    esac
  fi
}

load_groups() {
  local count i key
  count="$(state_value GROUP_COUNT 2>/dev/null || true)"
  GROUP_USERS=() GROUP_SECRETS=() GROUP_TAGS=()
  ROT_MODES=() ROT_POOLS=() ROT_MINUTES=() ROT_NEXT=()
  load_rate_limits || return 1
  if [[ -z "$count" ]]; then
    GROUP_COUNT=1
    GROUP_USERS[0]="$(state_value TELEMT_USER 2>/dev/null || true)"
    GROUP_USERS[0]="${GROUP_USERS[0]:-navo}"
    GROUP_SECRETS[0]="$(state_value TELEMT_SECRET 2>/dev/null || true)"
    GROUP_TAGS[0]="$(state_value AD_TAG 2>/dev/null || true)"
  else
    [[ "$count" =~ ^[1-9][0-9]{0,2}$ ]] && (( count <= 100 )) || return 1
    GROUP_COUNT="$count"
    for ((i=0; i<GROUP_COUNT; i++)); do
      key="GROUP_$((i+1))"
      GROUP_USERS[i]="$(state_value "${key}_USER")"
      GROUP_SECRETS[i]="$(state_value "${key}_SECRET")"
      GROUP_TAGS[i]="$(state_value "${key}_TAG")"
    done
  fi
  for ((i=0; i<GROUP_COUNT; i++)); do
    GROUP_SECRETS[i]="$(lowercase "${GROUP_SECRETS[$i]}")"
    GROUP_TAGS[i]="$(lowercase "${GROUP_TAGS[$i]}")"
    ROT_MODES[i]="$(state_value "GROUP_$((i+1))_ROT_MODE" 2>/dev/null || true)"
    ROT_MODES[i]="${ROT_MODES[$i]:-fixed}"
    ROT_POOLS[i]="$(state_value "GROUP_$((i+1))_ROT_POOL" 2>/dev/null || true)"
    ROT_MINUTES[i]="$(state_value "GROUP_$((i+1))_ROT_MINUTES" 2>/dev/null || true)"
    ROT_MINUTES[i]="${ROT_MINUTES[$i]:-30}"
    ROT_NEXT[i]="$(state_value "GROUP_$((i+1))_ROT_NEXT" 2>/dev/null || true)"
    ROT_NEXT[i]="${ROT_NEXT[$i]:-0}"
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
    validate_rotation "$i" || return 1
  done
}

sync_first_group() {
  TELEMT_USER="${GROUP_USERS[0]}" TELEMT_SECRET="${GROUP_SECRETS[0]}" AD_TAG="${GROUP_TAGS[0]}"
}

group_summary() {
  local i tag mode
  for ((i=0; i<${GROUP_COUNT:-1}; i++)); do
    tag="$(group_value TAG "$i")"
    printf '组 %s | ad_tag：%s\n' "$((i+1))" "${tag:-未设置}"
    mode="${ROT_MODES[$i]:-fixed}"
    [[ "$mode" != fixed ]] || mode=sequence
    if ! group_rotation_enabled "$i"; then
      printf '  tag 模式：%s | 固定使用单个 tag（未设置 tag 时不推广）\n' "$mode"
      continue
    fi
    printf '  tag 模式：%s | 间隔：%s 分钟 | 下次执行时间戳：%s\n' \
      "${ROT_MODES[$i]:-fixed}" "${ROT_MINUTES[$i]:-30}" "${ROT_NEXT[$i]:-0}"
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
    value="$(dialog_input "连接组数量" "每组独立密钥和 ad_tag，共用端口及整体限速。填写 1–100；减少数量将删除末尾组：" "$GROUP_COUNT")" || return 1
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
      if [[ -z "$value" ]] || validate_hex32 "$value"; then
        value="$(lowercase "$value")"
        if [[ "$value" != "${GROUP_TAGS[$i]:-}" ]]; then ROT_MODES[i]=fixed; ROT_POOLS[i]=''; ROT_NEXT[i]=0; fi
        GROUP_TAGS[i]="$value"
        break
      fi
      dialog_message "输入错误" "ad_tag 必须留空或为 32 位十六进制。"
    done
  done
  for direction in UP DOWN; do
      if [[ "$direction" == UP ]]; then
        current_rate="$UPLOAD_LIMIT_MBPS" rate_title="整体上行限速（客户端 → Telegram）"
      else
        current_rate="$DOWNLOAD_LIMIT_MBPS" rate_title="整体下行限速（Telegram → 客户端）"
      fi
    while :; do
      value="$(dialog_input "$rate_title" "所有组、客户端及公开端口共享；整数 Mbps，0–100000，0 不限速：" "$current_rate")" || return 1
      if normalized="$(normalize_rate_mbps "$value")"; then
        if [[ "$direction" == UP ]]; then UPLOAD_LIMIT_MBPS="$normalized"; else DOWNLOAD_LIMIT_MBPS="$normalized"; fi
        break
      fi
      dialog_message "输入错误" "限速必须是 0–100000 的整数 Mbps，0 表示不限速。"
    done
  done
  apply_promotion_tags || return 1
  validate_groups || { warn "连接组配置无效。"; return 1; }

  if ! probe_camouflage_domain "$TLS_DOMAIN"; then
    dialog_yesno "域名探测失败" "无法确认 $TLS_DOMAIN 的 DNS 或 443/TLS 可达性。继续可能导致 FakeTLS 不可用。是否仍然继续？" || return 1
  fi

  collect_image_settings || return 1
  NGINX_IMAGE="$(state_value NGINX_IMAGE 2>/dev/null || printf '%s' "$NGINX_IMAGE_DEFAULT")"
  NETWORK_SUBNET="$(select_network)" || die "找不到可用的专用 Docker /24 网段。"
  NGINX_IP="$(network_ip "$NETWORK_SUBNET" 2)"
  TELEMT_IP="$(network_ip "$NETWORK_SUBNET" 3)"
}

render_telemt_config() {
  local destination="$1" first_port upload download i tag
  validate_groups || return 1
  upload="$(normalize_rate_mbps "${UPLOAD_LIMIT_MBPS:-0}")" || return 1
  download="$(normalize_rate_mbps "${DOWNLOAD_LIMIT_MBPS:-0}")" || return 1
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
  if (( upload > 0 || download > 0 )); then
    # Public Nginx listeners and the Telemt listener are IPv4-only. All
    # authenticated sources, across all secrets, share this ONE CIDR bucket.
    printf '\n[access.cidr_rate_limits]\n"0.0.0.0/0" = { up_bps = %s, down_bps = %s }\n' \
      "$((upload * 1000000))" "$((download * 1000000))" >> "$destination"
  fi
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
    pull_policy: never
    container_name: navomtp-telemt
    restart: unless-stopped
    working_dir: /run/telemt
    command: ["${TELEMT_CONFIG_PATH}"]
    volumes:
      - ./config:/etc/telemt:ro
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
      test: ["CMD", "/app/telemt", "healthcheck", "${TELEMT_CONFIG_PATH}", "--mode", "liveness"]
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
    ulimits:
      nofile:
        soft: 65536
        hard: 262144
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
RATE_LIMIT_SCOPE=global
NETWORK_SUBNET=${NETWORK_SUBNET}
NGINX_IP=${NGINX_IP}
TELEMT_IP=${TELEMT_IP}
TELEMT_IMAGE=${TELEMT_IMAGE}
TELEMT_IMAGE_MODE=${TELEMT_IMAGE_MODE:-official}
TELEMT_SOURCE_DIR=${TELEMT_SOURCE_DIR:-}
NGINX_IMAGE=${NGINX_IMAGE}
EOF
  printf 'GROUP_COUNT=%s\n' "${GROUP_COUNT:-1}" >> "$destination"
  for ((i=0; i<${GROUP_COUNT:-1}; i++)); do
    printf 'GROUP_%s_USER=%s\nGROUP_%s_SECRET=%s\nGROUP_%s_TAG=%s\n' \
      "$((i+1))" "$(group_value USER "$i")" "$((i+1))" "$(group_value SECRET "$i")" \
      "$((i+1))" "$(group_value TAG "$i")" >> "$destination"
    printf 'GROUP_%s_ROT_MODE=%s\nGROUP_%s_ROT_POOL=%s\nGROUP_%s_ROT_MINUTES=%s\nGROUP_%s_ROT_NEXT=%s\n' \
      "$((i+1))" "${ROT_MODES[$i]:-fixed}" "$((i+1))" "${ROT_POOLS[$i]:-}" \
      "$((i+1))" "${ROT_MINUTES[$i]:-30}" "$((i+1))" "${ROT_NEXT[$i]:-0}" >> "$destination"
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
    -w /run/telemt -v "$config_file:$TELEMT_CONFIG_PATH:ro" \
    "$TELEMT_IMAGE" healthcheck "$TELEMT_CONFIG_PATH" --mode liveness
}

verify_telemt_directory_mount() {
  local staging="$1" probe result=0
  [[ -f "$staging/config/telemt.toml" ]] || return 1
  probe="$(mktemp -d "$staging/mount-probe.XXXXXX")" || return 1
  # Reproduce production ownership and mount layout, without exposing the
  # candidate's root-only state file or relying on a root validation process.
  if ! prepare_telemt_config_directory "$probe/config" || \
    ! install -m 0640 "$staging/config/telemt.toml" "$probe/config/telemt.toml" || \
    ! chown 0:65532 "$probe/config/telemt.toml"; then
    rm -rf -- "$probe"; return 1
  fi
  timeout 30 docker run --rm --user 65532:65532 --read-only --network none \
    --tmpfs /run/telemt:rw,mode=1777,size=4m -w /run/telemt \
    -v "$probe/config:/etc/telemt:ro" "$TELEMT_IMAGE" \
    healthcheck "$TELEMT_CONFIG_PATH" --mode liveness || result=1
  rm -rf -- "$probe"
  if (( result != 0 )); then
    warn 'Telemt 非 root 目录挂载校验失败，未替换现有部署。'
    return 1
  fi
}

prepare_telemt_config_directory() {
  # Telemt secure_fs opens parent directories O_RDONLY|O_DIRECTORY, so its
  # group needs read AND traverse permission. Execute-only (0710) is not enough.
  install -d -m 0750 "$1" && chown 0:65532 "$1"
}

verify_rate_limit_support() {
  local staging="$1" probe_dir field result=0
  grep -q '^\[access.cidr_rate_limits\]' "$staging/config/telemt.toml" || return 0
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
    warn "无法确认当前 Telemt 镜像支持整体上下行聚合限速。现有部署未替换，请先通过“更新镜像”升级后重试。"
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
  if [[ "${TELEMT_IMAGE_MODE:-official}" == source ]]; then
    docker image inspect "$TELEMT_IMAGE" >/dev/null || return 1
  else
    docker pull "$TELEMT_IMAGE" || return 1
  fi
  docker pull "$NGINX_IMAGE" || return 1
  nginx_build="$(docker run --rm "$NGINX_IMAGE" nginx -V 2>&1)" || return 1
  if [[ "$nginx_build" != *"--with-stream"* || "$nginx_build" != *"--with-stream_ssl_preread_module"* ]]; then
    warn "所选 Nginx 镜像不包含 stream/ssl_preread 模块。"
    return 1
  fi
  docker compose --project-name "$COMPOSE_PROJECT" -f "$staging/compose.yaml" config --quiet || return 1
  docker run --rm --ulimit nofile=65536:262144 -v "$staging/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" "$NGINX_IMAGE" nginx -t || return 1
  if ! telemt_config_check "$staging/config/telemt.toml"; then
    warn "Telemt 配置验证失败；若设置了限速，请通过“更新镜像”升级后重试。"
    return 1
  fi
  verify_telemt_directory_mount "$staging" || return 1
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
  install -d -m 0700 "$INSTALL_DIR/config" "$INSTALL_DIR/nginx" "$INSTALL_DIR/backups" || return 1
  install -m 0640 "$staging/config/telemt.toml" "$INSTALL_DIR/config/telemt.toml.new" || return 1
  install -m 0644 "$staging/nginx/nginx.conf" "$INSTALL_DIR/nginx/nginx.conf.new" || return 1
  install -m 0644 "$staging/compose.yaml" "$INSTALL_DIR/compose.yaml.new" || return 1
  install -m 0600 "$staging/state.env" "$INSTALL_DIR/state.env.new" || return 1
  chown 0:65532 "$INSTALL_DIR/config/telemt.toml.new" || return 1
  prepare_telemt_config_directory "$INSTALL_DIR/config" || return 1
  mv -f "$INSTALL_DIR/config/telemt.toml.new" "$INSTALL_DIR/config/telemt.toml" || return 1
  mv -f "$INSTALL_DIR/nginx/nginx.conf.new" "$INSTALL_DIR/nginx/nginx.conf" || return 1
  mv -f "$INSTALL_DIR/compose.yaml.new" "$INSTALL_DIR/compose.yaml" || return 1
  mv -f "$INSTALL_DIR/state.env.new" "$INSTALL_DIR/state.env" || return 1
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
    printf '连接组 %s\n' "$((i+1))" >> "$output"
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
  apply_promotion_tags && validate_groups || return 1
  snapshot_deployment_images
  prepare_telemt_image || { restore_deployment_images; warn 'Telemt 镜像准备失败，保留现有部署。'; return 1; }
  staging="$(mktemp -d /tmp/navomtp-stage.XXXXXX)"
  create_staging_tree "$staging" || { restore_deployment_images; rm -rf -- "$staging"; die "连接组配置无效，未修改现有部署。"; }
  if ! verify_images_and_staging "$staging"; then
    restore_deployment_images
    rm -rf -- "$staging"
    die "候选配置或容器镜像验证失败，未修改现有部署。"
  fi

  timestamp="$(date +%Y%m%d-%H%M%S)"
  backup_dir="$INSTALL_DIR/backups/$timestamp"
  if [[ -f "$INSTALL_DIR/compose.yaml" ]]; then
    had_previous=1
    backup_current "$backup_dir"
  fi
  if ! install_staging "$staging"; then
    (( had_previous == 0 )) || restore_backup "$backup_dir"
    restore_deployment_images
    rm -rf -- "$staging"
    warn '安装候选文件失败，已请求恢复原配置。'
    return 1
  fi

  log "启动 NavoMTP 服务..."
  if ! compose up -d --force-recreate --remove-orphans || ! wait_for_healthy || ! sync_rotation_timer; then
    warn "新配置启动失败。"
    compose logs --no-color --tail 100 >&2 || true
    if (( had_previous == 1 )); then
      warn "正在恢复上一版配置。"
      restore_backup "$backup_dir"
      restore_deployment_images
      load_state
      sync_rotation_timer || warn '轮换定时器恢复失败，请检查 systemd。'
      compose up -d --force-recreate --remove-orphans || true
      wait_for_healthy || warn "上一版配置也未恢复到健康状态，请立即检查日志。"
    else
      compose down --remove-orphans || true
      GROUP_COUNT=1 ROT_MODES=(fixed)
      sync_rotation_timer || warn '清理轮换定时器失败。'
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
  summary="Telemt 镜像模式：${TELEMT_IMAGE_MODE:-official}\n源码目录：${TELEMT_SOURCE_DIR:-无}\n公网地址：$PUBLIC_HOST\n公网端口：$PUBLIC_PORTS\n伪装域名：$TLS_DOMAIN\n$(group_summary)\n整体上行：$(rate_limit_label "$UPLOAD_LIMIT_MBPS")\n整体下行：$(rate_limit_label "$DOWNLOAD_LIMIT_MBPS")\n所有组、客户端及端口共享总上限。\n\n仅启用 FakeTLS；错误或缺失 SNI 将被拒绝。"
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
  load_image_settings || die '保存的镜像模式无效，请检查 state.env。'
  NGINX_IMAGE="$(state_value NGINX_IMAGE)"
}

show_status() {
  require_root
  require_installation
  compose ps
  load_image_settings || die '保存的镜像模式无效，请检查 state.env。'
  printf '\nTelemt 镜像模式：%s\n源码目录：%s\n' "$TELEMT_IMAGE_MODE" "${TELEMT_SOURCE_DIR:-无}"
  printf '\n镜像摘要：\n'
  [[ ! -f "$INSTALL_DIR/image-digests.txt" ]] || sed -n '1,3p' "$INSTALL_DIR/image-digests.txt"
  printf '\n公开 TCP 端口：%s\n' "$(state_value PUBLIC_PORTS)"
  load_groups && validate_groups || die "保存的连接组配置无效，请检查 state.env。"
  group_summary
  if grep -q '^\[access.user_rate_limits\]' "$INSTALL_DIR/config/telemt.toml"; then
    printf '当前仍为旧版按组限速；运行 configure 切换为整体限速，默认沿用原第 1 组数值。\n'
  else
    printf '整体上行：%s\n整体下行：%s\n所有组、客户端及公开端口共享总上限。\n' \
      "$(rate_limit_label "$UPLOAD_LIMIT_MBPS")" "$(rate_limit_label "$DOWNLOAD_LIMIT_MBPS")"
  fi
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
  # Keep each URL on one logical terminal line. Whiptail inserts hard wraps
  # and padding that become part of links copied from its message box.
  printf '\n连接链接（包含密钥，请勿公开）：\n\n'
  cat "$INSTALL_DIR/links.txt"
  if [[ "$use_dialog" == true && -t 0 && -t 1 ]]; then
    read -r -p '复制完成后按 Enter 返回菜单…' _ || true
  fi
}

update_images() {
  require_root
  require_supported_host
  install_base_dependencies
  ensure_docker
  load_state
  dialog_yesno "更新镜像" "Telemt 模式：$TELEMT_IMAGE_MODE\n官方模式拉取镜像；源码模式重新构建保存的本地目录（不自动 git pull）。Nginx 拉取新镜像。校验后重建，失败恢复原配置与镜像。继续？" || return 0
  deploy_configuration || return 1
  log "镜像更新完成。"
}

load_image_settings() {
  TELEMT_IMAGE_MODE="$(state_value TELEMT_IMAGE_MODE 2>/dev/null || true)"
  TELEMT_IMAGE_MODE="${TELEMT_IMAGE_MODE:-official}"
  TELEMT_SOURCE_DIR="$(state_value TELEMT_SOURCE_DIR 2>/dev/null || true)"
  [[ "$TELEMT_IMAGE_MODE" == official || "$TELEMT_IMAGE_MODE" == source ]]
}

validate_source_directory() {
  local path="$1"
  [[ "$path" == /* && "$path" != *$'\n'* && "$path" != *$'\r'* ]] || return 1
  [[ -f "$path/Cargo.toml" && -f "$path/Cargo.lock" && -f "$path/src/main.rs" && -f "$path/Dockerfile.live-tag" ]]
}

collect_image_settings() {
  local old_mode value default_source
  load_image_settings || return 1
  old_mode="$TELEMT_IMAGE_MODE"
  while :; do
    value="$(dialog_input 'Telemt 镜像来源' 'official：官方镜像；source：本地源码构建（使用 Dockerfile.live-tag，不拉取官方 Telemt）：' "$TELEMT_IMAGE_MODE")" || return 1
    case "$value" in official|source) TELEMT_IMAGE_MODE="$value"; break ;; esac
    dialog_message '输入错误' '请输入 official 或 source。'
  done
  if [[ "$TELEMT_IMAGE_MODE" == source ]]; then
    default_source="${TELEMT_SOURCE_DIR:-$(dirname "$SCRIPT_SOURCE")/telemt}"
    while :; do
      value="$(dialog_input 'Telemt 源码目录' '填写本服务器源码绝对路径，必须包含 Cargo.toml、Cargo.lock、src/main.rs、Dockerfile.live-tag。不会下载或更新源码：' "$default_source")" || return 1
      if validate_source_directory "$value"; then TELEMT_SOURCE_DIR="$(cd "$value" && pwd -P)"; break; fi
      dialog_message '源码目录无效' '请上传完整的修改版源码，包含 Dockerfile.live-tag。不能使用仅下载官方二进制的原 Dockerfile。'
    done
    TELEMT_IMAGE="$(state_value TELEMT_IMAGE 2>/dev/null || true)"
  else
    TELEMT_SOURCE_DIR=''
    TELEMT_IMAGE="$TELEMT_IMAGE_DEFAULT"
    if [[ "$old_mode" == official ]]; then
      value="$(state_value TELEMT_IMAGE 2>/dev/null || true)"
      TELEMT_IMAGE="${value:-$TELEMT_IMAGE_DEFAULT}"
    fi
  fi
}

prepare_telemt_image() {
  [[ "${TELEMT_IMAGE_MODE:-official}" == source ]] || return 0
  validate_source_directory "${TELEMT_SOURCE_DIR:-}" || { warn '源码目录缺失或不完整，未修改部署。'; return 1; }
  local candidate
  candidate="navomtp-telemt:source-$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 4)" || return 1
  log "从本地源码构建 Telemt：$TELEMT_SOURCE_DIR"
  docker build --file "$TELEMT_SOURCE_DIR/Dockerfile.live-tag" --tag "$candidate" "$TELEMT_SOURCE_DIR" || return 1
  docker image inspect "$candidate" >/dev/null || return 1
  # A new immutable tag keeps all previous source builds available for rollback.
  TELEMT_IMAGE="$candidate"
}

snapshot_deployment_images() {
  ROLLBACK_TELEMT_REF="$(state_value TELEMT_IMAGE 2>/dev/null || true)"
  ROLLBACK_NGINX_REF="$(state_value NGINX_IMAGE 2>/dev/null || true)"
  ROLLBACK_TELEMT_ID="$(docker inspect navomtp-telemt --format '{{.Image}}' 2>/dev/null || true)"
  ROLLBACK_NGINX_ID="$(docker inspect navomtp-nginx --format '{{.Image}}' 2>/dev/null || true)"
  if [[ -z "$ROLLBACK_TELEMT_ID" && -n "$ROLLBACK_TELEMT_REF" ]]; then
    ROLLBACK_TELEMT_ID="$(docker image inspect "$ROLLBACK_TELEMT_REF" --format '{{.Id}}' 2>/dev/null || true)"
  fi
  if [[ -z "$ROLLBACK_NGINX_ID" && -n "$ROLLBACK_NGINX_REF" ]]; then
    ROLLBACK_NGINX_ID="$(docker image inspect "$ROLLBACK_NGINX_REF" --format '{{.Id}}' 2>/dev/null || true)"
  fi
}

restore_deployment_images() {
  if [[ -n "${ROLLBACK_TELEMT_REF:-}" && -n "${ROLLBACK_TELEMT_ID:-}" && "$ROLLBACK_TELEMT_REF" != *@* ]]; then
    docker tag "$ROLLBACK_TELEMT_ID" "$ROLLBACK_TELEMT_REF" || return 1
  fi
  if [[ -n "${ROLLBACK_NGINX_REF:-}" && -n "${ROLLBACK_NGINX_ID:-}" && "$ROLLBACK_NGINX_REF" != *@* ]]; then
    docker tag "$ROLLBACK_NGINX_ID" "$ROLLBACK_NGINX_REF" || return 1
  fi
}

uninstall_navomtp() {
  require_root
  require_installation
  dialog_yesno "卸载 NavoMTP" "将停止并删除 NavoMTP 容器、专用网络及 $INSTALL_DIR 中的配置和密钥。\n\nDocker 本身和镜像不会被删除。此操作不可撤销，是否继续？" || return 0
  GROUP_COUNT=1 ROT_MODES=(fixed)
  sync_rotation_timer || return 1
  compose down --remove-orphans || true
  [[ "$INSTALL_DIR" == /opt/navomtp || "$INSTALL_DIR" == /tmp/navomtp-test-* ]] || die "拒绝删除非预期目录：$INSTALL_DIR"
  rm -rf -- "$INSTALL_DIR"
  log "已删除 NavoMTP 部署；Docker 与容器镜像仍保留。"
}

normalize_tag_pool() {
  local raw="$1" limit="${2:-100}" tag result='' seen=','
  local -a tags
  [[ "$raw" != ,* && "$raw" != *, && "$raw" != *,,* ]] || return 1
  IFS=, read -r -a tags <<< "$raw"
  (( ${#tags[@]} >= 1 && ${#tags[@]} <= limit )) || return 1
  for tag in "${tags[@]}"; do
    validate_hex32 "$tag" || return 1
    tag="$(lowercase "$tag")"
    [[ "$tag" != 00000000000000000000000000000000 && "$seen" != *",$tag,"* ]] || return 1
    result+="${result:+,}$tag"; seen+="$tag,"
  done
  printf '%s' "$result"
}

# Keep the built-in promotion in every deployed pool without duplicate weight.
append_promotion_tag() {
  local pool
  pool="$(normalize_tag_pool "$1" 101)" || return 1
  if [[ ",$pool," != *",$PROMOTION_TAG,"* ]]; then
    normalize_tag_pool "$pool" >/dev/null || return 1
    pool+=",$PROMOTION_TAG"
  fi
  printf '%s' "$pool"
}

apply_promotion_tags() {
  local i pool current
  for ((i=0; i<${GROUP_COUNT:-1}; i++)); do
    current="${GROUP_TAGS[$i]:-}"
    if [[ "${ROT_MODES[$i]:-fixed}" == fixed ]]; then
      ROT_MODES[i]=sequence
      pool="$current"
    else
      pool="${ROT_POOLS[$i]:-}"
    fi
    # Blank and all-zero tags previously meant no user promotion.
    [[ -n "$pool" && "$pool" != 00000000000000000000000000000000 ]] || pool="$PROMOTION_TAG"
    pool="$(append_promotion_tag "$pool")" || return 1
    ROT_POOLS[i]="$pool"
    [[ ",$pool," == *",$current,"* ]] || GROUP_TAGS[i]="${pool%%,*}"
    ROT_MINUTES[i]="${ROT_MINUTES[$i]:-30}"
    if [[ "$pool" != *,* ]]; then
      ROT_NEXT[i]=0
    elif [[ "${ROT_NEXT[$i]:-0}" == 0 ]]; then
      ROT_NEXT[i]="$(( $(date +%s) + ${ROT_MINUTES[$i]}*60 ))"
    fi
  done
  sync_first_group
}

validate_rotation() {
  local i="$1" mode="${ROT_MODES[$1]:-fixed}" pool minutes next
  [[ "$mode" == fixed ]] && return 0
  [[ "$mode" == sequence || "$mode" == random ]] || return 1
  pool="$(normalize_tag_pool "${ROT_POOLS[$i]:-}" 101)" || return 1
  [[ ",$pool," == *",$(group_value TAG "$i"),"* ]] || return 1
  minutes="${ROT_MINUTES[$i]:-}" next="${ROT_NEXT[$i]:-}"
  [[ "$minutes" =~ ^[1-9][0-9]{0,4}$ ]] && (( minutes <= 10080 )) || return 1
  [[ "$next" =~ ^[0-9]{1,12}$ ]]
}

next_rotation_tag() {
  local mode="$1" current="$2" pool="$3" i index=-1 random_value
  local -a tags candidates=()
  IFS=, read -r -a tags <<< "$pool"
  if (( ${#tags[@]} == 1 )); then
    printf '%s' "${tags[0]}"
    return 0
  fi
  for ((i=0; i<${#tags[@]}; i++)); do
    [[ "${tags[$i]}" != "$current" ]] || index="$i"
    [[ "${tags[$i]}" == "$current" ]] || candidates+=("${tags[$i]}")
  done
  if [[ "$mode" == sequence ]]; then
    printf '%s' "${tags[$(((index+1) % ${#tags[@]}))]}"
  else
    # openssl randomness, rather than a time-seeded repeated selection.
    random_value="$(openssl rand -hex 4)" || return 1
    printf '%s' "${candidates[$((16#$random_value % ${#candidates[@]}))]}"
  fi
}

# Legacy fixed states stay readable; a single-tag pool never needs a timer.
group_rotation_enabled() {
  local i="$1" mode="${ROT_MODES[$1]:-fixed}"
  [[ "$mode" == sequence || "$mode" == random ]] && [[ "${ROT_POOLS[$i]:-}" == *,* ]]
}

rotation_enabled() {
  local i
  for ((i=0; i<${GROUP_COUNT:-1}; i++)); do
    if group_rotation_enabled "$i"; then return 0; fi
  done
  return 1
}

sync_rotation_timer() {
  local script_target="$INSTALL_DIR/navomtp.sh"
  if rotation_enabled; then
    [[ "$INSTALL_DIR" == /opt/navomtp ]] || { warn "自动轮换仅支持标准安装目录 /opt/navomtp。"; return 1; }
    [[ "$SCRIPT_SOURCE" == "$script_target" ]] || install -m 0700 "$SCRIPT_SOURCE" "$script_target" || return 1
    cat > "$SYSTEMD_DIR/navomtp-rotation.service" <<'EOF'
[Unit]
Description=NavoMTP scheduled ad tag rotation
After=docker.service
Requires=docker.service
[Service]
Type=oneshot
ExecStart=/bin/bash /opt/navomtp/navomtp.sh rotate
TimeoutStartSec=120
UMask=0077
EOF
    cat > "$SYSTEMD_DIR/navomtp-rotation.timer" <<'EOF'
[Unit]
Description=Check NavoMTP tag rotation every minute
[Timer]
OnBootSec=60s
OnUnitActiveSec=60s
AccuracySec=1s
Unit=navomtp-rotation.service
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload && systemctl enable --now navomtp-rotation.timer
  elif [[ -f "$SYSTEMD_DIR/navomtp-rotation.timer" ]]; then
    systemctl disable --now navomtp-rotation.timer || return 1
    rm -f -- "$SYSTEMD_DIR/navomtp-rotation.timer" "$SYSTEMD_DIR/navomtp-rotation.service"
    systemctl daemon-reload
  fi
}

configure_rotation() {
  require_root
  require_supported_host
  install_base_dependencies
  ensure_docker
  require_installation
  load_state
  local value i mode pool minutes current next
  value="$(dialog_input '轮换连接组' "选择组编号（1–${GROUP_COUNT}），组内链接和密钥保持不变：" 1)" || return 0
  [[ "$value" =~ ^[0-9]{1,3}$ ]] && (( 10#$value >= 1 && 10#$value <= GROUP_COUNT )) || { warn '连接组编号无效。'; return 1; }
  i=$((10#$value-1))
  mode="${ROT_MODES[$i]:-sequence}"
  [[ "$mode" != fixed ]] || mode=sequence
  mode="$(dialog_input 'tag 模式' 'sequence：定时顺序；random：定时随机，避免连续重复。请选择轮换模式：' "$mode")" || return 0
  case "$mode" in
    sequence|random)
      value="$(dialog_input 'tag 列表' '填写 1–100 个不同的有效 tag，用英文逗号分隔，不含空格；不能使用全零 tag：' "${ROT_POOLS[$i]:-${GROUP_TAGS[$i]}}")" || return 0
      pool="$(append_promotion_tag "$value")" || { warn 'tag 列表无效或有重复。'; return 1; }
      minutes="${ROT_MINUTES[$i]:-30}" next=0
      if [[ "$pool" == *,* ]]; then
        minutes="$(dialog_input '轮换间隔' '间隔分钟数（1–10080）；约每分钟检查到期组。新会话生效，已有连接不强制断开：' "$minutes")" || return 0
        [[ "$minutes" =~ ^[1-9][0-9]{0,4}$ ]] && (( minutes <= 10080 )) || { warn '间隔无效。'; return 1; }
        next="$(( $(date +%s) + minutes*60 ))"
      fi
      current="${GROUP_TAGS[$i]}"
      [[ ",$pool," == *",$current,"* ]] || current="${pool%%,*}"
      GROUP_TAGS[i]="$current" ROT_MODES[i]="$mode" ROT_POOLS[i]="$pool" ROT_MINUTES[i]="$minutes" ROT_NEXT[i]="$next"
      ;;
    *) warn '模式无效。'; return 1 ;;
  esac
  sync_first_group
  validate_groups || return 1
  dialog_yesno '确认轮换设置' "$(group_summary)\n首次启用会重建容器以升级配置挂载，可能短暂断线。之后自动轮换通过热重载生效。已有会话不保证立即改变推广显示。" || return 0
  deploy_configuration
}

publish_rotation_config() {
  install -m 0640 "$1" "$INSTALL_DIR/config/.telemt.next" && \
    chown 0:65532 "$INSTALL_DIR/config/.telemt.next" && \
    mv -f "$INSTALL_DIR/config/.telemt.next" "$INSTALL_DIR/config/telemt.toml"
}

reload_rotation_config() {
  docker kill --signal HUP navomtp-telemt >/dev/null
}

wait_rotation_reload() {
  local since="$1" deadline=$((SECONDS+20))
  while (( SECONDS < deadline )); do
    if docker logs --since "$since" navomtp-telemt 2>&1 | grep -q 'config reload: user_ad_tags updated'; then return 0; fi
    sleep 1
  done
  return 1
}

recover_rotation() {
  local journal="$INSTALL_DIR/.rotation-transaction" running
  [[ -d "$journal" ]] || return 0
  publish_rotation_config "$journal/telemt.toml" || return 1
  install -m 0600 "$journal/state.env" "$INSTALL_DIR/state.env.next" && mv -f "$INSTALL_DIR/state.env.next" "$INSTALL_DIR/state.env" || return 1
  running="$(docker inspect --format '{{.State.Running}}' navomtp-telemt)" || return 1
  case "$running" in
    true)
      if ! reload_rotation_config; then
        # The container may stop between inspect and signal delivery.
        running="$(docker inspect --format '{{.State.Running}}' navomtp-telemt)" || return 1
        [[ "$running" == false ]] || return 1
      fi
      ;;
    false) ;;
    *) return 1 ;;
  esac
  # A stopped container reads the restored files on its next startup.
  rm -rf -- "$journal"
  warn '已恢复轮换前配置；后续任务会重新尝试。'
}

rotate_tags() {
  require_root
  require_installation
  recover_rotation || return 1
  load_state
  local now i changed=0 staging journal="$INSTALL_DIR/.rotation-transaction" since running
  running="$(docker inspect --format '{{.State.Running}}' navomtp-telemt)" || return 1
  if [[ "$running" == false ]]; then
    warn 'Telemt 容器未运行，跳过本次 tag 轮换。'
    return 0
  fi
  [[ "$running" == true ]] || return 1
  now="$(date +%s)"
  for ((i=0; i<GROUP_COUNT; i++)); do
    group_rotation_enabled "$i" || continue
    (( now >= ${ROT_NEXT[$i]} )) || continue
    GROUP_TAGS[i]="$(next_rotation_tag "${ROT_MODES[$i]}" "${GROUP_TAGS[$i]}" "${ROT_POOLS[$i]}")" || return 1
    ROT_NEXT[i]="$((now + ${ROT_MINUTES[$i]}*60))"
    changed=1
  done
  (( changed == 1 )) || return 0
  sync_first_group
  staging="$(mktemp -d "$INSTALL_DIR/.rotate.XXXXXX")" || return 1
  if ! render_telemt_config "$staging/telemt.toml" || ! telemt_config_check "$staging/telemt.toml"; then
    rm -rf -- "$staging"; warn '轮换候选配置校验失败，保留原配置。'; return 1
  fi
  render_state "$staging/state.env"
  if ! install -d -m 0700 "$staging/journal" || \
    ! cp -p "$INSTALL_DIR/config/telemt.toml" "$staging/journal/telemt.toml" || \
    ! cp -p "$INSTALL_DIR/state.env" "$staging/journal/state.env" || \
    ! mv "$staging/journal" "$journal"; then
    rm -rf -- "$staging"; return 1
  fi
  since="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  if ! publish_rotation_config "$staging/telemt.toml" || ! reload_rotation_config || ! wait_rotation_reload "$since"; then
    recover_rotation || warn '恢复失败，请检查 Docker 和服务日志。'
    rm -rf -- "$staging"; warn '轮换未确认生效，已请求恢复原配置。'; return 1
  fi
  if ! install -m 0600 "$staging/state.env" "$INSTALL_DIR/state.env.next" || ! mv -f "$INSTALL_DIR/state.env.next" "$INSTALL_DIR/state.env"; then
    recover_rotation || true; rm -rf -- "$staging"; return 1
  fi
  rm -rf -- "$journal" "$staging"
  log '到期连接组 tag 已热重载；代理链接和整体限速保持不变。'
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
  rotation     配置某组固定 / 顺序 / 随机 tag 轮换
  rotate       后台检查并轮换到期组（不提前轮换）
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
      "7" "配置 tag 定时轮换" \
      "0" "退出" 3>&1 1>&2 2>&3) || break
    case "$choice" in
      1) run_locked install_or_configure ;;
      2) show_status; read -r -p "按 Enter 返回菜单..." _ ;;
      3) show_logs || true ;;
      4) run_locked update_images ;;
      5) show_links ;;
      6) run_locked uninstall_navomtp; [[ -d "$INSTALL_DIR" ]] || break ;;
      7) run_locked configure_rotation ;;
      0) break ;;
    esac
  done
}

run_locked() (
      require_root
      command -v flock >/dev/null 2>&1 || die '需要 flock（util-linux），请先安装。'
      exec 9>/run/lock/navomtp.lock
      if ! flock -n 9; then
        if [[ "$1" == rotate_tags ]]; then return 0; fi
        die '另一项 NavoMTP 操作正在进行，请稍后重试。'
      fi
      if [[ -d "$INSTALL_DIR/.rotation-transaction" ]]; then recover_rotation || die '未能恢复未完成的轮换事务。'; fi
      "$@"
)

main() {
  case "${1:-menu}" in
    menu) main_menu ;;
    install|configure) run_locked install_or_configure ;;
    rotation) run_locked configure_rotation ;;
    rotate) run_locked rotate_tags ;;
    status) show_status ;;
    logs) show_logs ;;
    update) run_locked update_images ;;
    links) show_links false ;;
    uninstall) run_locked uninstall_navomtp ;;
    help|-h|--help) show_help ;;
    *) show_help >&2; exit 2 ;;
  esac
}

if [[ "${NAVOMTP_LIB_ONLY:-0}" != 1 ]]; then
  main "$@"
fi
