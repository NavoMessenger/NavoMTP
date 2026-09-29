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
assert_success "valid username" validate_username navo-user_1
assert_failure "username injection" validate_username 'navo" = "bad'
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

tmp_dir="$(mktemp -d /tmp/navomtp-tests.XXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT
PUBLIC_HOST="proxy.example.com"
PUBLIC_PORTS="12432,22124,32332"
TELEMT_USER="navo"
TELEMT_SECRET="0123456789abcdef0123456789abcdef"
AD_TAG="abcdef0123456789abcdef0123456789"
TLS_DOMAIN="www.microsoft.com"
NETWORK_SUBNET="172.29.241.0/24"
NGINX_IP="172.29.241.2"
TELEMT_IP="172.29.241.3"
TELEMT_IMAGE="$TELEMT_IMAGE_DEFAULT"
NGINX_IMAGE="$NGINX_IMAGE_DEFAULT"

create_staging_tree "$tmp_dir/stage"
assert_contains "telemt internal port" "$tmp_dir/stage/config/telemt.toml" 'port = 9443'
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
assert_not_contains "compose does not publish telemt internal port" "$tmp_dir/stage/compose.yaml" '"9443:9443'
assert_not_contains "compose does not publish API" "$tmp_dir/stage/compose.yaml" '9091:'
assert_not_contains "compose does not publish metrics" "$tmp_dir/stage/compose.yaml" '9090:'

mode_secret="$(stat -c '%a' "$tmp_dir/stage/config/telemt.toml" 2>/dev/null || stat -f '%Lp' "$tmp_dir/stage/config/telemt.toml")"
assert_equal "secret config mode" "600" "$mode_secret"

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

printf '1..%d\n' "$((pass + fail))"
(( fail == 0 ))
