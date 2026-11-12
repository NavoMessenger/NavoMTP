#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export NAVOMTP_LIB_ONLY=1
source "$ROOT_DIR/navomtp.sh"
test_dir="$(mktemp -d /tmp/navomtp-remove-promotion.XXXXXX)"
trap 'rm -rf -- "$test_dir"' EXIT
INSTALL_DIR="$test_dir/install"
PUBLIC_HOST=proxy.example.com PUBLIC_PORTS=12432 TLS_DOMAIN=www.microsoft.com
NETWORK_SUBNET=172.29.241.0/24 NGINX_IP=172.29.241.2 TELEMT_IP=172.29.241.3
TELEMT_IMAGE="$TELEMT_IMAGE_DEFAULT" NGINX_IMAGE="$NGINX_IMAGE_DEFAULT"
UPLOAD_LIMIT_MBPS=10 DOWNLOAD_LIMIT_MBPS=25
GROUP_COUNT=6
GROUP_USERS=(navo navo_2 navo_3 navo_4 navo_5 navo_6)
GROUP_SECRETS=()
for ((i=1; i<=GROUP_COUNT; i++)); do
  printf -v secret '%032x' "$i"
  GROUP_SECRETS+=("$secret")
done
a=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
b=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
GROUP_TAGS=("$PROMOTION_TAG" "$a" "$PROMOTION_TAG" "$PROMOTION_TAG" "$a" '')
ROT_MODES=(sequence random sequence fixed fixed fixed)
ROT_POOLS=("$a,$PROMOTION_TAG,$b" "$a,$PROMOTION_TAG" "$PROMOTION_TAG" '' '' '')
ROT_MINUTES=(30 10 30 30 30 30) ROT_NEXT=(123 456 0 0 0 0)
sync_first_group
create_staging_tree "$INSTALL_DIR"
require_root() { return 0; }
require_supported_host() { return 0; }
install_base_dependencies() { return 0; }
ensure_docker() { return 0; }
# The deployment boundary must not reintroduce the tag after removal.
deploy_configuration() {
  apply_promotion_tags && validate_groups || return 1
  render_telemt_config "$INSTALL_DIR/config/telemt.toml"
  render_state "$INSTALL_DIR/state.env"
}
remove_promotion_tags
load_state
[[ "${ROT_POOLS[0]}" == "$a,$b" && "${GROUP_TAGS[0]}" == "$a" && "${ROT_NEXT[0]}" == 123 ]]
[[ "${ROT_MODES[1]}" == random && "${ROT_POOLS[1]}" == "$a" && "${GROUP_TAGS[1]}" == "$a" && "${ROT_NEXT[1]}" == 0 ]]
for i in 2 3 5; do
  [[ -z "${GROUP_TAGS[$i]}" && -z "${ROT_POOLS[$i]}" && "${ROT_MODES[$i]}" == fixed && "${ROT_NEXT[$i]}" == 0 ]]
done
[[ "${GROUP_TAGS[4]}" == "$a" && "${ROT_MODES[4]}" == fixed ]]
[[ "$UPLOAD_LIMIT_MBPS" == 10 && "$DOWNLOAD_LIMIT_MBPS" == 25 && "$PUBLIC_PORTS" == 12432 ]]
for ((i=0; i<GROUP_COUNT; i++)); do
  [[ "${PROMOTION_DISABLED[$i]}" == 1 ]]
  printf -v secret '%032x' "$((i+1))"
  [[ "${GROUP_SECRETS[$i]}" == "$secret" ]]
done
! grep -Fq "$PROMOTION_TAG" "$INSTALL_DIR/config/telemt.toml"
rotation_enabled
before="$(<"$INSTALL_DIR/state.env")"
remove_promotion_tags
[[ "$(<"$INSTALL_DIR/state.env")" == "$before" ]]
# When all surviving pools are singletons or empty, no timer is needed.
GROUP_TAGS[0]="$a" ROT_POOLS[0]="$a" ROT_NEXT[0]=0
render_state "$INSTALL_DIR/state.env"
remove_promotion_tags
! rotation_enabled
before="$(<"$INSTALL_DIR/state.env")"
deploy_configuration() { return 1; }
if remove_promotion_tags; then exit 1; fi
[[ "$(<"$INSTALL_DIR/state.env")" == "$before" ]]
# The public command dispatches through the shared operation lock.
run_locked() { [[ "$1" == remove_promotion_tags ]]; }
main remove-promotion
printf 'ok - remove across groups, persistence, idempotence, timers, failure and command dispatch\n'
