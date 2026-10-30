#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2034
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export NAVOMTP_LIB_ONLY=1
source "$ROOT_DIR/navomtp.sh"
image_test_dir="$(mktemp -d /tmp/navomtp-image-tests.XXXXXX)"
trap 'rm -rf -- "$image_test_dir"' EXIT
pass=0 fail=0
run_case() (
  local scenario="$1" original image_before
  INSTALL_DIR="$image_test_dir/$scenario/deployment"
  SYSTEMD_DIR="$image_test_dir/units"
  local source_dir="$image_test_dir/$scenario/source tree"
  mkdir -p "$source_dir/src"
  touch "$source_dir/Cargo.toml" "$source_dir/Cargo.lock" "$source_dir/src/main.rs" "$source_dir/Dockerfile.live-tag"
  local calls="$image_test_dir/$scenario/docker.calls"
  : > "$calls"
  docker() {
    printf '%s\n' "$*" >> "$calls"
    case "$*" in
      build*) [[ "$scenario" != build-failure ]] ;;
      'inspect navomtp-telemt'*) printf 'old-telemt-id' ;;
      'inspect navomtp-nginx'*) printf 'old-nginx-id' ;;
      *'nginx -V'*) printf '%s' '--with-stream --with-stream_ssl_preread_module' ;;
      *) return 0 ;;
    esac
  }
  PUBLIC_HOST=proxy.example.com PUBLIC_PORTS=12432 TLS_DOMAIN=www.microsoft.com
  GROUP_COUNT=1 GROUP_USERS=(navo) GROUP_SECRETS=(11111111111111111111111111111111) GROUP_TAGS=('')
  ROT_MODES=(fixed) ROT_POOLS=('') ROT_MINUTES=(30) ROT_NEXT=(0)
  UPLOAD_LIMIT_MBPS=10 DOWNLOAD_LIMIT_MBPS=25
  NETWORK_SUBNET=172.29.241.0/24 NGINX_IP=172.29.241.2 TELEMT_IP=172.29.241.3
  TELEMT_IMAGE="$TELEMT_IMAGE_DEFAULT" NGINX_IMAGE="$NGINX_IMAGE_DEFAULT"
  TELEMT_IMAGE_MODE=official TELEMT_SOURCE_DIR=''
  sync_first_group
  create_staging_tree "$INSTALL_DIR"
  original="$(<"$INSTALL_DIR/state.env")"
  verify_telemt_directory_mount() { return 0; }
  telemt_config_check() { return 0; }
  verify_rate_limit_support() { return 0; }
  verify_ad_tag_support() { return 0; }
  sync_rotation_timer() { return 0; }
  write_links() { return 0; }
  show_links() { return 0; }
  record_image_digests() { return 0; }
  maybe_configure_ufw() { return 0; }
  install_staging() { cp -Rp "$1/." "$INSTALL_DIR/"; }
  compose() {
    if [[ "$scenario" == startup-failure && "$1" == up && ! -e "$INSTALL_DIR/failed-once" ]]; then
      touch "$INSTALL_DIR/failed-once"; return 1
    fi
    return 0
  }
  wait_for_healthy() { return 0; }
  case "$scenario" in
    official)
      verify_images_and_staging "$INSTALL_DIR" || return 1
      grep -Fq "pull $TELEMT_IMAGE_DEFAULT" "$calls" || return 1
      ! grep -q '^build' "$calls" ;;
    legacy)
      sed '/^TELEMT_IMAGE_MODE=/d; /^TELEMT_SOURCE_DIR=/d' "$INSTALL_DIR/state.env" > "$INSTALL_DIR/legacy"
      cp "$INSTALL_DIR/legacy" "$INSTALL_DIR/state.env"
      load_state || return 1
      [[ "$TELEMT_IMAGE_MODE" == official && -z "$TELEMT_SOURCE_DIR" ]] ;;
    source|rebuild|missing|build-failure|startup-failure)
      TELEMT_IMAGE_MODE=source TELEMT_SOURCE_DIR="$source_dir"
      case "$scenario" in
        missing) TELEMT_SOURCE_DIR="$source_dir/absent"; ! prepare_telemt_image; return ;;
        build-failure)
          if deploy_configuration; then return 1; fi
          [[ "$(<"$INSTALL_DIR/state.env")" == "$original" ]]; return ;;
      esac
      if [[ "$scenario" == startup-failure ]]; then
        if deploy_configuration; then return 1; fi
        [[ "$(<"$INSTALL_DIR/state.env")" == "$original" ]] || return 1
        grep -Fq "tag old-telemt-id $TELEMT_IMAGE_DEFAULT" "$calls"
      else
        prepare_telemt_image || return 1
        [[ "$TELEMT_IMAGE" == navomtp-telemt:source-* ]] || return 1
        image_before="$TELEMT_IMAGE"
        if [[ "$scenario" == rebuild ]]; then
          prepare_telemt_image || return 1
          [[ "$TELEMT_IMAGE" != "$image_before" ]] || return 1
        fi
        create_staging_tree "$INSTALL_DIR"
        verify_images_and_staging "$INSTALL_DIR" || return 1
        grep -Fq -- "--file $source_dir/Dockerfile.live-tag" "$calls" || return 1
        ! grep -q '^pull .*telemt' "$calls" || return 1
        load_state || return 1
        [[ "$TELEMT_IMAGE_MODE" == source && "$TELEMT_SOURCE_DIR" == "$source_dir" ]]
      fi ;;
    update-source)
      TELEMT_IMAGE_MODE=source TELEMT_SOURCE_DIR="$source_dir"
      create_staging_tree "$INSTALL_DIR"
      require_root() { return 0; }
      require_supported_host() { return 0; }
      install_base_dependencies() { return 0; }
      ensure_docker() { return 0; }
      dialog_yesno() { return 0; }
      update_images || return 1
      load_state || return 1
      [[ "$TELEMT_IMAGE_MODE" == source && "$TELEMT_IMAGE" == navomtp-telemt:source-* ]] || return 1
      ! grep -q '^pull .*telemt' "$calls" ;;
    wizard-source|wizard-official)
      if [[ "$scenario" == wizard-official ]]; then
        TELEMT_IMAGE_MODE=source TELEMT_SOURCE_DIR="$source_dir" TELEMT_IMAGE=navomtp-telemt:previous
        create_staging_tree "$INSTALL_DIR"
      fi
      dialog_input() {
        case "$1" in
          'Telemt 镜像来源') if [[ "$scenario" == wizard-source ]]; then printf source; else printf official; fi ;;
          'Telemt 源码目录') printf '%s' "$source_dir" ;;
        esac
      }
      collect_image_settings || return 1
      if [[ "$scenario" == wizard-source ]]; then
        [[ "$TELEMT_IMAGE_MODE" == source && "$TELEMT_SOURCE_DIR" == "$(cd "$source_dir" && pwd -P)" ]]
      else
        [[ "$TELEMT_IMAGE_MODE" == official && "$TELEMT_IMAGE" == "$TELEMT_IMAGE_DEFAULT" && -z "$TELEMT_SOURCE_DIR" ]]
      fi ;;
  esac
)
for scenario in official legacy source rebuild missing build-failure startup-failure update-source wizard-source wizard-official; do
  if run_case "$scenario"; then printf 'ok - %s\n' "$scenario"; pass=$((pass+1)); else printf 'not ok - %s\n' "$scenario"; fail=$((fail+1)); fi
done
printf '1..%s\n' "$((pass+fail))"
(( fail == 0 ))
