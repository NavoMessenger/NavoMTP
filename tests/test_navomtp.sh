#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2034
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export NAVOMTP_LIB_ONLY=1
source "$ROOT_DIR/navomtp.sh"

pass=0
fail=0

assert_success() {
  local name="$1"
  shift
  if "$@"; then
    printf 'ok - %s\n' "$name"
    pass=$((pass + 1))
  else
    printf 'not ok - %s\n' "$name"
    fail=$((fail + 1))
  fi
}

assert_failure() {
  local name="$1"
  shift
  if "$@"; then
    printf 'not ok - %s\n' "$name"
    fail=$((fail + 1))
  else
    printf 'ok - %s\n' "$name"
    pass=$((pass + 1))
  fi
}

assert_equal() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    printf 'ok - %s\n' "$name"
    pass=$((pass + 1))
  else
    printf 'not ok - %s (expected=%q actual=%q)\n' "$name" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

assert_contains() {
  local name="$1" file="$2" needle="$3"
  if grep -Fq -- "$needle" "$file"; then
    printf 'ok - %s\n' "$name"
    pass=$((pass + 1))
  else
    printf 'not ok - %s (missing %q)\n' "$name" "$needle"
    fail=$((fail + 1))
  fi
}

assert_not_contains() {
  local name="$1" file="$2" needle="$3"
  if grep -Fq -- "$needle" "$file"; then
    printf 'not ok - %s (unexpected %q)\n' "$name" "$needle"
    fail=$((fail + 1))
  else
    printf 'ok - %s\n' "$name"
    pass=$((pass + 1))
  fi
}

assert_success "valid secret" validate_hex32 0123456789abcdef0123456789abcdef
assert_failure "short secret" validate_hex32 0123456789abcdef
assert_failure "secret injection" validate_hex32 '0123456789abcdef0123456789abcde"'
assert_success "valid domain" validate_domain www.microsoft.com
assert_failure "domain scheme rejected" validate_domain https://example.com
assert_failure "domain wildcard rejected" validate_domain '*.example.com'
assert_failure "domain injection rejected" validate_domain 'example.com;include'
assert_success "valid IPv4" validate_ipv4 203.0.113.10
assert_failure "invalid IPv4" validate_ipv4 999.1.1.1
assert_equal "normalize multiple ports" "443,12432,22124" "$(normalize_ports '443, 12432,22124')"
assert_failure "duplicate ports" normalize_ports '443,443'
assert_failure "zero port" normalize_ports '0'
assert_failure "oversized port" normalize_ports '65536'
assert_failure "port injection" normalize_ports '443;id'
assert_equal "unlimited rate" 0 "$(normalize_rate_mbps 0)"
assert_equal "positive rate" 25 "$(normalize_rate_mbps 25)"
assert_equal "maximum rate" 100000 "$(normalize_rate_mbps 100000)"
assert_equal "leading zero decimal rate" 8 "$(normalize_rate_mbps 000008)"
assert_failure "empty rate" normalize_rate_mbps ''
assert_failure "negative rate" normalize_rate_mbps -1
assert_failure "fractional rate" normalize_rate_mbps 1.5
assert_failure "oversized rate" normalize_rate_mbps 100001
assert_failure "overflow rate" normalize_rate_mbps 999999999999999999999
assert_failure "rate injection" normalize_rate_mbps '1;id'
assert_equal "unlimited display" '不限速' "$(rate_limit_label 0)"
assert_equal "limited display" '25 Mbps' "$(rate_limit_label 25)"

tmp_dir="$(mktemp -d /tmp/navomtp-tests.XXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT
export NAVOMTP_SYSTEMD_DIR="$tmp_dir/units"
SYSTEMD_DIR="$NAVOMTP_SYSTEMD_DIR"
mkdir -p "$SYSTEMD_DIR"
PUBLIC_HOST="proxy.example.com"
PUBLIC_PORTS="12432,22124,32332"
TELEMT_USER="$TELEMT_USER_DEFAULT"
TELEMT_SECRET="0123456789abcdef0123456789abcdef"
AD_TAG="abcdef0123456789abcdef0123456789"
TLS_DOMAIN="www.microsoft.com"
NETWORK_SUBNET="172.29.241.0/24"
NGINX_IP="172.29.241.2"
TELEMT_IP="172.29.241.3"
TELEMT_IMAGE="$TELEMT_IMAGE_DEFAULT"
NGINX_IMAGE="$NGINX_IMAGE_DEFAULT"

create_staging_tree "$tmp_dir/stage"
assert_not_contains "unlimited omits aggregate rate table" "$tmp_dir/stage/config/telemt.toml" '[access.cidr_rate_limits]'
assert_not_contains "no per-group limiter" "$tmp_dir/stage/config/telemt.toml" '[access.user_rate_limits]'
assert_contains "default upload state" "$tmp_dir/stage/state.env" 'UPLOAD_LIMIT_MBPS=0'
assert_contains "default download state" "$tmp_dir/stage/state.env" 'DOWNLOAD_LIMIT_MBPS=0'
assert_contains "telemt internal port" "$tmp_dir/stage/config/telemt.toml" 'port = 9443'
assert_contains "fixed internal telemt user" "$tmp_dir/stage/config/telemt.toml" '"navo" = "0123456789abcdef0123456789abcdef"'
assert_contains "telemt fake TLS only" "$tmp_dir/stage/config/telemt.toml" 'tls = true'
assert_contains "telemt proxy protocol" "$tmp_dir/stage/config/telemt.toml" 'proxy_protocol = true'
assert_contains "telemt trusts only nginx" "$tmp_dir/stage/config/telemt.toml" 'proxy_protocol_trusted_cidrs = ["172.29.241.2/32"]'
assert_contains "control API disabled" "$tmp_dir/stage/config/telemt.toml" 'enabled = false'
assert_contains "nginx exact SNI map" "$tmp_dir/stage/nginx/nginx.conf" 'www.microsoft.com telemt_backend;'
assert_contains "nginx rejects unknown SNI" "$tmp_dir/stage/nginx/nginx.conf" 'default reject_backend;'
assert_contains "nginx sends PROXY protocol" "$tmp_dir/stage/nginx/nginx.conf" 'proxy_protocol on;'
assert_contains "first public listener" "$tmp_dir/stage/nginx/nginx.conf" 'listen 12432 reuseport;'
assert_contains "third public listener" "$tmp_dir/stage/nginx/nginx.conf" 'listen 32332 reuseport;'
assert_contains "compose publishes nginx port" "$tmp_dir/stage/compose.yaml" '"12432:12432/tcp"'
assert_contains "directory mount uses generated filename for startup" "$tmp_dir/stage/compose.yaml" 'command: ["/etc/telemt/telemt.toml"]'
assert_contains "healthcheck uses generated filename" "$tmp_dir/stage/compose.yaml" '"healthcheck", "/etc/telemt/telemt.toml"'
assert_contains "telemt directory mount" "$tmp_dir/stage/compose.yaml" './config:/etc/telemt:ro'
assert_not_contains "obsolete container config filename" "$tmp_dir/stage/compose.yaml" '/etc/telemt/config.toml'
assert_not_contains "compose does not publish telemt internal port" "$tmp_dir/stage/compose.yaml" '"9443:9443'
assert_not_contains "compose does not publish API" "$tmp_dir/stage/compose.yaml" '9091:'
assert_not_contains "compose does not publish metrics" "$tmp_dir/stage/compose.yaml" '9090:'

mode_secret="$(stat -c '%a' "$tmp_dir/stage/config/telemt.toml" 2>/dev/null || stat -f '%Lp' "$tmp_dir/stage/config/telemt.toml")"
assert_equal "secret config mode" "600" "$mode_secret"

UPLOAD_LIMIT_MBPS=10
DOWNLOAD_LIMIT_MBPS=25
render_telemt_config "$tmp_dir/rates.toml"
assert_contains "aggregate Mbps conversion" "$tmp_dir/rates.toml" '"0.0.0.0/0" = { up_bps = 10000000, down_bps = 25000000 }'
UPLOAD_LIMIT_MBPS=100000
DOWNLOAD_LIMIT_MBPS=0
render_telemt_config "$tmp_dir/rates.toml"
assert_contains "upload only and maximum conversion" "$tmp_dir/rates.toml" '{ up_bps = 100000000000, down_bps = 0 }'
UPLOAD_LIMIT_MBPS=0
DOWNLOAD_LIMIT_MBPS=8
TELEMT_USER=legacy-user
render_telemt_config "$tmp_dir/rates.toml"
assert_contains "download aggregate independent of user" "$tmp_dir/rates.toml" '"0.0.0.0/0" = { up_bps = 0, down_bps = 8000000 }'
TELEMT_USER="$TELEMT_USER_DEFAULT"

INSTALL_DIR="$tmp_dir/state-tests"
create_staging_tree "$INSTALL_DIR"
UPLOAD_LIMIT_MBPS=999
DOWNLOAD_LIMIT_MBPS=999
load_state
assert_equal "load saved upload" 0 "$UPLOAD_LIMIT_MBPS"
assert_equal "load saved download" 8 "$DOWNLOAD_LIMIT_MBPS"
sed '/^UPLOAD_LIMIT_MBPS=/d; /^DOWNLOAD_LIMIT_MBPS=/d; /^GROUP_/d' "$INSTALL_DIR/state.env" > "$tmp_dir/old-state.env"
cp "$tmp_dir/old-state.env" "$INSTALL_DIR/state.env"
load_state
assert_equal "legacy upload defaults unlimited" 0 "$UPLOAD_LIMIT_MBPS"
assert_equal "legacy download defaults unlimited" 0 "$DOWNLOAD_LIMIT_MBPS"
unset GROUP_COUNT

# The compatibility probe must catch silent ignores, either unsupported
# direction, and unrelated failures rather than treating any error as support.
test_rate_support() (
  local support_mode="$1"
  UPLOAD_LIMIT_MBPS=10
  DOWNLOAD_LIMIT_MBPS=20
  create_staging_tree "$tmp_dir/support"
  telemt_config_check() {
    case "$support_mode" in
      supported) printf 'invalid type: string, expected u64\n' >&2; return 1 ;;
      ignored) return 0 ;;
      upload-only)
        if grep -q 'down_bps = "unsupported-probe"' "$1"; then return 0; fi
        printf 'invalid type: string, expected u64\n' >&2; return 1 ;;
      unrelated) printf 'Cannot connect to Docker\n' >&2; return 1 ;;
    esac
  }
  verify_rate_limit_support "$tmp_dir/support"
)
assert_success "native parser recognizes both directions" test_rate_support supported
assert_failure "silent ignored keys rejected" test_rate_support ignored
assert_failure "one unsupported direction rejected" test_rate_support upload-only
assert_failure "unrelated probe failure rejected" test_rate_support unrelated

test_rate_rollback() (
  INSTALL_DIR="$tmp_dir/rollback"
  UPLOAD_LIMIT_MBPS=10
  DOWNLOAD_LIMIT_MBPS=20
  create_staging_tree "$INSTALL_DIR"
  local original
  original="$(<"$INSTALL_DIR/state.env")"
  backup_current "$tmp_dir/backup"
  UPLOAD_LIMIT_MBPS=99
  DOWNLOAD_LIMIT_MBPS=88
  render_state "$INSTALL_DIR/state.env"
  render_telemt_config "$INSTALL_DIR/config/telemt.toml"
  restore_backup "$tmp_dir/backup"
  [[ "$(<"$INSTALL_DIR/state.env")" == "$original" ]] || return 1
  grep -Fq 'up_bps = 10000000, down_bps = 20000000' "$INSTALL_DIR/config/telemt.toml"
)
assert_success "rollback restores saved limits and config" test_rate_rollback

test_rate_wizard() (
  INSTALL_DIR="$tmp_dir/wizard"
  UPLOAD_LIMIT_MBPS=12
  DOWNLOAD_LIMIT_MBPS=34
  create_staging_tree "$INSTALL_DIR"
  dialog_input() {
    printf '%s\n' "$1" >> "$tmp_dir/prompts"
    case "$1" in
      '整体上行限速（客户端 → Telegram）') [[ "$3" == 12 ]] || return 1 ;;
      '整体下行限速（Telegram → 客户端）') [[ "$3" == 34 ]] || return 1 ;;
      'Telemt 用户') return 1 ;;
    esac
    printf '%s' "$3"
  }
  check_ports_available() { return 0; }
  probe_camouflage_domain() { return 0; }
  select_network() { printf '%s' '172.29.241.0/24'; }
  collect_configuration || return 1
  [[ "$UPLOAD_LIMIT_MBPS" == 12 && "$DOWNLOAD_LIMIT_MBPS" == 34 ]] || return 1
  [[ "$(grep '^整体.*限速' "$tmp_dir/prompts")" == $'整体上行限速（客户端 → Telegram）\n整体下行限速（Telegram → 客户端）' ]]
)
assert_success "wizard restores rates after domain without user prompt" test_rate_wizard

test_rate_update() (
  INSTALL_DIR="$tmp_dir/update"
  UPLOAD_LIMIT_MBPS=12
  DOWNLOAD_LIMIT_MBPS=34
  create_staging_tree "$INSTALL_DIR"
  local original
  original="$(<"$INSTALL_DIR/config/telemt.toml")"
  require_root() { return 0; }
  require_supported_host() { return 0; }
  install_base_dependencies() { return 0; }
  ensure_docker() { return 0; }
  dialog_yesno() { return 0; }
  docker() { printf 'test-image-id'; }
  compose() { return 0; }
  verify_images_and_staging() { [[ "$UPLOAD_LIMIT_MBPS" == 12 && "$DOWNLOAD_LIMIT_MBPS" == 34 ]]; }
  wait_for_healthy() { return 0; }
  record_image_digests() { return 0; }
  write_links() { return 0; }
  show_links() { return 0; }
  maybe_configure_ufw() { return 0; }
  install_staging() { cp -Rp "$1/." "$INSTALL_DIR/"; }
  update_images || return 1
  [[ "$(<"$INSTALL_DIR/config/telemt.toml")" == "$original" ]]
)
assert_success "image update loads and preserves independent rates" test_rate_update

test_rate_deploy_failure() (
  INSTALL_DIR="$tmp_dir/deploy-rollback"
  UPLOAD_LIMIT_MBPS=12
  DOWNLOAD_LIMIT_MBPS=34
  create_staging_tree "$INSTALL_DIR"
  local original
  original="$(<"$INSTALL_DIR/state.env")"
  UPLOAD_LIMIT_MBPS=99
  DOWNLOAD_LIMIT_MBPS=88
  verify_images_and_staging() { return 0; }
  # Exercise the real backup and rollback flow without requiring root chown.
  install_staging() {
    cp "$1/state.env" "$INSTALL_DIR/state.env"
    cp "$1/config/telemt.toml" "$INSTALL_DIR/config/telemt.toml"
  }
  compose() { return 0; }
  wait_for_healthy() { return 1; }
  if deploy_configuration; then return 1; fi
  [[ "$(<"$INSTALL_DIR/state.env")" == "$original" ]] || return 1
  grep -Fq 'up_bps = 12000000, down_bps = 34000000' "$INSTALL_DIR/config/telemt.toml"
)
assert_success "failed deployment restores previous limits" test_rate_deploy_failure

INSTALL_DIR="$tmp_dir/link-output"
mkdir -p "$INSTALL_DIR"
PUBLIC_PORTS="12432,22124,32332"
extract_base_link() {
  printf '%s' 'tg://proxy?server=proxy.example.com&port=12432&secret=ee0123456789abcdef0123456789abcdef7777772e6d6963726f736f66742e636f6d'
}
write_links
assert_contains "second tg link uses second public port" "$INSTALL_DIR/links.txt" 'tg://proxy?server=proxy.example.com&port=22124&secret=ee'
assert_contains "https link generated from official tg link" "$INSTALL_DIR/links.txt" 'https://t.me/proxy?server=proxy.example.com&port=32332&secret=ee'
mode_links="$(stat -c '%a' "$INSTALL_DIR/links.txt" 2>/dev/null || stat -f '%Lp' "$INSTALL_DIR/links.txt")"
assert_equal "links file mode" "600" "$mode_links"

test_multi_groups() (
  local scenario="$1" first second domain_hex original
  # Restore actual implementations after the earlier log-link stub.
  source "$ROOT_DIR/navomtp.sh"
  INSTALL_DIR="$tmp_dir/multi-$scenario"
  first=11111111111111111111111111111111
  second=22222222222222222222222222222222
  GROUP_COUNT=2
  GROUP_USERS=(navo navo_2)
  GROUP_SECRETS=("$first" "$second")
  GROUP_TAGS=(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa '')
  UPLOAD_LIMIT_MBPS=12
  DOWNLOAD_LIMIT_MBPS=34
  sync_first_group
  create_staging_tree "$INSTALL_DIR" || return 1
  case "$scenario" in
    render)
      grep -Fq '"navo_2" = "22222222222222222222222222222222"' "$INSTALL_DIR/config/telemt.toml" || return 1
      grep -Fq '"navo" = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$INSTALL_DIR/config/telemt.toml" || return 1
      grep -Fq '"0.0.0.0/0" = { up_bps = 12000000, down_bps = 34000000 }' "$INSTALL_DIR/config/telemt.toml" || return 1
      [[ "$(grep -c '^\[access.cidr_rate_limits\]' "$INSTALL_DIR/config/telemt.toml")" == 1 ]] || return 1
      ! grep -q '^\[access.user_rate_limits\]' "$INSTALL_DIR/config/telemt.toml" || return 1
      ! grep -q '^GROUP_.*_UPLOAD_MBPS=' "$INSTALL_DIR/state.env" || return 1
      ! grep -q '^ad_tag =' "$INSTALL_DIR/config/telemt.toml" ;;
    tags)
      GROUP_TAGS[1]=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      render_telemt_config "$INSTALL_DIR/config/telemt.toml" || return 1
      grep -Fq '"navo_2" = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' "$INSTALL_DIR/config/telemt.toml" ;;
    roundtrip)
      original="$(<"$INSTALL_DIR/config/telemt.toml")"
      GROUP_TAGS=() GROUP_SECRETS=()
      load_state || return 1
      render_telemt_config "$INSTALL_DIR/reloaded.toml" || return 1
      [[ "$(<"$INSTALL_DIR/reloaded.toml")" == "$original" ]] ;;
    duplicate)
      GROUP_SECRETS=(abcdefabcdefabcdefabcdefabcdefab ABCDEFABCDEFABCDEFABCDEFABCDEFAB)
      ! validate_groups ;;
    invalid-tag) GROUP_TAGS[1]='bad"tag'; ! validate_groups ;;
    invalid-user) GROUP_USERS[1]='bad"user'; ! validate_groups ;;
    duplicate-user) GROUP_USERS[1]=navo; ! validate_groups ;;
    invalid-count) GROUP_COUNT=0; ! validate_groups ;;
    legacy)
      sed '/^GROUP_/d' "$INSTALL_DIR/state.env" > "$INSTALL_DIR/legacy.env"
      cp "$INSTALL_DIR/legacy.env" "$INSTALL_DIR/state.env"
      load_state || return 1
      [[ "$GROUP_COUNT" == 1 && "${GROUP_SECRETS[0]}" == "$first" && "${GROUP_TAGS[0]}" == aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]] ;;
    global-migration)
      sed '/^RATE_LIMIT_SCOPE=/d' "$INSTALL_DIR/state.env" > "$INSTALL_DIR/old.env"
      printf 'GROUP_1_UPLOAD_MBPS=12\nGROUP_1_DOWNLOAD_MBPS=34\nGROUP_2_UPLOAD_MBPS=90\nGROUP_2_DOWNLOAD_MBPS=80\n' >> "$INSTALL_DIR/old.env"
      cp "$INSTALL_DIR/old.env" "$INSTALL_DIR/state.env"
      load_state || return 1
      [[ "$UPLOAD_LIMIT_MBPS" == 12 && "$DOWNLOAD_LIMIT_MBPS" == 34 ]] || return 1
      sync_first_group
      [[ "$UPLOAD_LIMIT_MBPS" == 12 && "$DOWNLOAD_LIMIT_MBPS" == 34 ]] || return 1
      create_staging_tree "$INSTALL_DIR/new" || return 1
      grep -q '^RATE_LIMIT_SCOPE=global$' "$INSTALL_DIR/new/state.env" || return 1
      ! grep -q '^GROUP_.*_UPLOAD_MBPS=' "$INSTALL_DIR/new/state.env" || return 1
      grep -Fq '"0.0.0.0/0" = { up_bps = 12000000, down_bps = 34000000 }' "$INSTALL_DIR/new/config/telemt.toml" ;;
    global-unlimited)
      UPLOAD_LIMIT_MBPS=0 DOWNLOAD_LIMIT_MBPS=0
      render_telemt_config "$INSTALL_DIR/unlimited.toml" || return 1
      ! grep -q 'rate_limits' "$INSTALL_DIR/unlimited.toml" ;;
    global-wizard)
      dialog_input() {
        printf '%s\n' "$1" >> "$INSTALL_DIR/prompts"
        case "$1" in
          '整体上行限速（客户端 → Telegram）') printf 5 ;;
          '整体下行限速（Telegram → 客户端）') printf 9 ;;
          *) printf '%s' "$3" ;;
        esac
      }
      check_ports_available() { return 0; }
      probe_camouflage_domain() { return 0; }
      select_network() { printf '172.29.241.0/24'; }
      collect_configuration || return 1
      [[ "$UPLOAD_LIMIT_MBPS" == 5 && "$DOWNLOAD_LIMIT_MBPS" == 9 && "$GROUP_COUNT" == 2 ]] || return 1
      [[ "$(grep -c '整体.*限速' "$INSTALL_DIR/prompts")" == 2 ]] || return 1
      ! grep -q '组 .*限速' "$INSTALL_DIR/prompts" ;;
    aggregate-rate)
      telemt_config_check() { printf 'invalid type: string, expected u64\n' >&2; return 1; }
      verify_rate_limit_support "$INSTALL_DIR" ;;
    tag-support)
      telemt_config_check() {
        grep -q '"navomtp_type_probe" = 123' "$1" || return 0
        printf 'invalid type: integer, expected string\n' >&2
        return 1
      }
      verify_ad_tag_support "$INSTALL_DIR" ;;
    ignored-tags)
      telemt_config_check() { return 0; }
      ! verify_ad_tag_support "$INSTALL_DIR" ;;
    links|missing-link)
      domain_hex="$(printf '%s' "$TLS_DOMAIN" | od -An -tx1 | tr -d ' \n')"
      compose() {
        printf 'tg://proxy?server=proxy.example.com&port=12432&secret=dd%s\n' "$first"
        printf 'tg://proxy?server=proxy.example.com&port=12432&secret=ee%s%s\n' "$second" "$domain_hex"
        printf 'tg://proxy?server=proxy.example.com&port=12432&secret=ee%s%s\n' "$first" "$domain_hex"
      }
      if [[ "$scenario" == missing-link ]]; then
        extract_base_link() { [[ "$1" == "$first" ]] || return 1; printf 'tg://proxy?server=x&port=1&secret=ee%s' "$1"; }
        write_links || return 1
        [[ ! -e "$INSTALL_DIR/links.txt" ]]
      else
        PUBLIC_PORTS=12432,22124
        write_links || return 1
        [[ "$(grep -c '^tg://' "$INSTALL_DIR/links.txt")" == 4 ]] || return 1
        [[ "$(grep -c '^https://' "$INSTALL_DIR/links.txt")" == 4 ]] || return 1
        grep -Fq "port=22124&secret=ee$second$domain_hex" "$INSTALL_DIR/links.txt" || return 1
        grep -Fq "port=22124&secret=ee$first$domain_hex" "$INSTALL_DIR/links.txt" || return 1
        ! grep -q 'secret=dd' "$INSTALL_DIR/links.txt"
      fi ;;
    rollback)
      original="$(<"$INSTALL_DIR/state.env")"
      backup_current "$INSTALL_DIR/backup"
      GROUP_COUNT=1
      render_state "$INSTALL_DIR/state.env"
      render_telemt_config "$INSTALL_DIR/config/telemt.toml"
      restore_backup "$INSTALL_DIR/backup" || return 1
      load_state || return 1
      [[ "$GROUP_COUNT" == 2 && "$(<"$INSTALL_DIR/state.env")" == "$original" ]] ;;
    update)
      original="$(<"$INSTALL_DIR/state.env")"
      require_root() { return 0; }
      require_supported_host() { return 0; }
      install_base_dependencies() { return 0; }
      ensure_docker() { return 0; }
      dialog_yesno() { return 0; }
      docker() { printf 'test-image'; }
      compose() { return 0; }
      verify_images_and_staging() { [[ "$GROUP_COUNT" == 2 && "$UPLOAD_LIMIT_MBPS" == 12 && "${GROUP_TAGS[0]}" == aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]]; }
      wait_for_healthy() { return 0; }
      record_image_digests() { return 0; }
      write_links() { return 0; }
      show_links() { return 0; }
      maybe_configure_ufw() { return 0; }
      install_staging() { cp -Rp "$1/." "$INSTALL_DIR/"; }
      update_images || return 1
      [[ "$(<"$INSTALL_DIR/state.env")" == "$original" ]] ;;
    wizard-add|wizard-remove|wizard-cancel)
      original="$(<"$INSTALL_DIR/state.env")"
      dialog_input() {
        case "$1" in
          '连接组数量') if [[ "$scenario" == wizard-add ]]; then printf 3; else printf 1; fi ;;
          '组 3：访问密钥') printf 33333333333333333333333333333333 ;;
          '组 3：广告标签') printf cccccccccccccccccccccccccccccccc ;;
          *) printf '%s' "$3" ;;
        esac
      }
      dialog_yesno() { [[ "$scenario" != wizard-cancel ]]; }
      check_ports_available() { return 0; }
      probe_camouflage_domain() { return 0; }
      select_network() { printf '172.29.241.0/24'; }
      if [[ "$scenario" == wizard-cancel ]]; then
        if collect_configuration; then return 1; fi
        [[ "$(<"$INSTALL_DIR/state.env")" == "$original" ]]
      else
        collect_configuration || return 1
        [[ "${GROUP_SECRETS[0]}" == "$first" ]] || return 1
        render_telemt_config "$INSTALL_DIR/new.toml" || return 1
        if [[ "$scenario" == wizard-add ]]; then
          [[ "$GROUP_COUNT" == 3 && "${GROUP_TAGS[2]}" == cccccccccccccccccccccccccccccccc ]]
        else
          [[ "$GROUP_COUNT" == 1 ]] || return 1
          ! grep -q 'navo_2' "$INSTALL_DIR/new.toml"
        fi
      fi ;;
  esac
)
for scenario in render tags roundtrip duplicate invalid-tag invalid-user duplicate-user invalid-count legacy global-migration global-unlimited global-wizard aggregate-rate tag-support ignored-tags links missing-link rollback update wizard-add wizard-remove wizard-cancel; do
  assert_success "multi-group $scenario" test_multi_groups "$scenario"
done

printf '1..%d\n' "$((pass + fail))"
(( fail == 0 ))
