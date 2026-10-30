#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2034
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export NAVOMTP_LIB_ONLY=1
source "$ROOT_DIR/navomtp.sh"
test_dir="$(mktemp -d /tmp/navomtp-rotation-tests.XXXXXX)"
trap 'rm -rf -- "$test_dir"' EXIT
pass=0 fail=0
check() {
  local name="$1"; shift
  if "$@"; then printf 'ok - %s\n' "$name"; pass=$((pass+1)); else printf 'not ok - %s\n' "$name"; fail=$((fail+1)); fi
}

test_case() (
  local scenario="$1" old_state old_config tag i
  local a=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa b=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb c=cccccccccccccccccccccccccccccccc
  INSTALL_DIR="$test_dir/$scenario"
  PUBLIC_HOST=proxy.example.com PUBLIC_PORTS=12432,22124 TLS_DOMAIN=www.microsoft.com
  NETWORK_SUBNET=172.29.241.0/24 NGINX_IP=172.29.241.2 TELEMT_IP=172.29.241.3
  TELEMT_IMAGE="$TELEMT_IMAGE_DEFAULT" NGINX_IMAGE="$NGINX_IMAGE_DEFAULT"
  UPLOAD_LIMIT_MBPS=10 DOWNLOAD_LIMIT_MBPS=25
  GROUP_COUNT=1 GROUP_USERS=(navo) GROUP_SECRETS=(11111111111111111111111111111111) GROUP_TAGS=("$a")
  ROT_MODES=(sequence) ROT_POOLS=("$a,$b,$c") ROT_MINUTES=(30) ROT_NEXT=(0)
  sync_first_group
  create_staging_tree "$INSTALL_DIR" || return 1
  old_state="$(<"$INSTALL_DIR/state.env")" old_config="$(<"$INSTALL_DIR/config/telemt.toml")"
  require_root() { return 0; }
  telemt_config_check() { [[ "$scenario" != invalid-config ]]; }
  publish_rotation_config() { cp "$1" "$INSTALL_DIR/config/telemt.toml"; }
  reload_rotation_config() { [[ "$scenario" != signal-failure ]]; }
  wait_rotation_reload() { [[ "$scenario" != reload-failure ]]; }
  case "$scenario" in
    pool) [[ "$(normalize_tag_pool "$a,$b")" == "$a,$b" ]] ;;
    duplicate) ! normalize_tag_pool "$a,$a" ;;
    malformed) ! normalize_tag_pool "$a,invalid" ;;
    singleton) ! normalize_tag_pool "$a" ;;
    zero) ! normalize_tag_pool "$a,00000000000000000000000000000000" ;;
    trailing-comma) ! normalize_tag_pool "$a,$b," ;;
    sequence) [[ "$(next_rotation_tag sequence "$a" "$a,$b,$c")" == "$b" ]] ;;
    wrap) [[ "$(next_rotation_tag sequence "$c" "$a,$b,$c")" == "$a" ]] ;;
    random)
      for ((i=0; i<30; i++)); do
        tag="$(next_rotation_tag random "$a" "$a,$b,$c")" || return 1
        [[ "$tag" == "$b" || "$tag" == "$c" ]] || return 1
      done ;;
    validate-invalid-interval) ROT_MINUTES=(0); ! validate_groups ;;
    validate-invalid-mode) ROT_MODES=(bad); ! validate_groups ;;
    validate-current-missing) ROT_POOLS=("$b,$c"); ! validate_groups ;;
    roundtrip)
      load_state || return 1
      [[ "${ROT_MODES[0]}" == sequence && "${ROT_POOLS[0]}" == "$a,$b,$c" && "${ROT_MINUTES[0]}" == 30 ]] ;;
    legacy)
      sed '/_ROT_/d' "$INSTALL_DIR/state.env" > "$INSTALL_DIR/legacy"
      cp "$INSTALL_DIR/legacy" "$INSTALL_DIR/state.env"
      load_state || return 1
      [[ "${ROT_MODES[0]}" == fixed && "${GROUP_TAGS[0]}" == "$a" ]] ;;
    not-due|fixed)
      if [[ "$scenario" == fixed ]]; then ROT_MODES=(fixed); else ROT_NEXT=(99999999999); fi
      render_state "$INSTALL_DIR/state.env"
      old_state="$(<"$INSTALL_DIR/state.env")"
      rotate_tags || return 1
      [[ "$(<"$INSTALL_DIR/state.env")" == "$old_state" && "$(<"$INSTALL_DIR/config/telemt.toml")" == "$old_config" ]] ;;
    tick)
      rotate_tags || return 1
      load_state || return 1
      [[ "${GROUP_TAGS[0]}" == "$b" && "${GROUP_SECRETS[0]}" == 11111111111111111111111111111111 ]] || return 1
      [[ "$UPLOAD_LIMIT_MBPS" == 10 && "$DOWNLOAD_LIMIT_MBPS" == 25 && "${ROT_NEXT[0]}" -gt "$(date +%s)" ]] || return 1
      [[ ! -e "$INSTALL_DIR/.rotation-transaction" ]] ;;
    reload-failure|invalid-config)
      if rotate_tags; then return 1; fi
      [[ "$(<"$INSTALL_DIR/state.env")" == "$old_state" && "$(<"$INSTALL_DIR/config/telemt.toml")" == "$old_config" ]] ;;
    signal-failure)
      if rotate_tags; then return 1; fi
      [[ -e "$INSTALL_DIR/.rotation-transaction/state.env" ]] ;;
    crash-recovery)
      mkdir "$INSTALL_DIR/.rotation-transaction"
      cp "$INSTALL_DIR/state.env" "$INSTALL_DIR/.rotation-transaction/state.env"
      cp "$INSTALL_DIR/config/telemt.toml" "$INSTALL_DIR/.rotation-transaction/telemt.toml"
      GROUP_TAGS=("$b")
      render_telemt_config "$INSTALL_DIR/config/telemt.toml"
      recover_rotation || return 1
      [[ "$(<"$INSTALL_DIR/config/telemt.toml")" == "$old_config" && ! -e "$INSTALL_DIR/.rotation-transaction" ]] ;;
    multi-due)
      GROUP_COUNT=2 GROUP_USERS=(navo navo_2)
      GROUP_SECRETS=(11111111111111111111111111111111 22222222222222222222222222222222)
      GROUP_TAGS=("$a" "$c") ROT_MODES=(sequence random) ROT_POOLS=("$a,$b,$c" "$a,$c") ROT_MINUTES=(30 10) ROT_NEXT=(0 0)
      create_staging_tree "$INSTALL_DIR" || return 1
      rotate_tags || return 1
      load_state || return 1
      [[ "${GROUP_TAGS[0]}" == "$b" && "${GROUP_TAGS[1]}" == "$a" ]] ;;
    timer)
      SYSTEMD_DIR="$INSTALL_DIR/units"; mkdir "$SYSTEMD_DIR"
      systemctl() { printf '%s\n' "$*" >> "$SYSTEMD_DIR/calls"; }
      install() { return 0; }
      INSTALL_DIR=/opt/navomtp
      sync_rotation_timer || return 1
      grep -q 'OnUnitActiveSec=60s' "$SYSTEMD_DIR/navomtp-rotation.timer" || return 1
      grep -q 'ExecStart=/bin/bash /opt/navomtp/navomtp.sh rotate' "$SYSTEMD_DIR/navomtp-rotation.service" || return 1
      grep -q 'enable --now navomtp-rotation.timer' "$SYSTEMD_DIR/calls" || return 1
      ROT_MODES=(fixed)
      sync_rotation_timer || return 1
      [[ ! -e "$SYSTEMD_DIR/navomtp-rotation.timer" ]] ;;
    mount)
      grep -Fq './config:/etc/telemt:ro' "$INSTALL_DIR/compose.yaml" ;;
    configure-sequence|configure-fixed)
      require_supported_host() { return 0; }
      install_base_dependencies() { return 0; }
      ensure_docker() { return 0; }
      dialog_input() {
        case "$1" in
          '轮换连接组') printf 1 ;;
          'tag 模式') if [[ "$scenario" == configure-fixed ]]; then printf fixed; else printf sequence; fi ;;
          'tag 列表') printf '%s' "$a,$b,$c" ;;
          '轮换间隔') printf 10 ;;
        esac
      }
      dialog_yesno() { return 0; }
      deploy_configuration() {
        touch "$INSTALL_DIR/deploy-called"
        [[ "${GROUP_SECRETS[0]}" == 11111111111111111111111111111111 && "${GROUP_TAGS[0]}" == "$a" ]] || return 1
        if [[ "$scenario" == configure-fixed ]]; then
          [[ "${ROT_MODES[0]}" == fixed && "${ROT_NEXT[0]}" == 0 ]]
        else
          [[ "${ROT_MODES[0]}" == sequence && "${ROT_MINUTES[0]}" == 10 && "${ROT_NEXT[0]}" -gt "$(date +%s)" ]]
        fi
      }
      configure_rotation || return 1
      [[ -e "$INSTALL_DIR/deploy-called" ]] ;;
  esac
)

for scenario in pool duplicate malformed singleton zero trailing-comma sequence wrap random validate-invalid-interval validate-invalid-mode validate-current-missing roundtrip legacy not-due fixed tick reload-failure invalid-config signal-failure crash-recovery multi-due timer mount configure-sequence configure-fixed; do
  check "$scenario" test_case "$scenario"
done
printf '1..%s\n' "$((pass+fail))"
(( fail == 0 ))
