#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export NAVOMTP_LIB_ONLY=1
source "$ROOT_DIR/navomtp.sh"
a=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
b=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
[[ "$(append_promotion_tag "$a,$b")" == "$a,$b,$PROMOTION_TAG" ]]
[[ "$(append_promotion_tag "$a,$PROMOTION_TAG")" == "$a,$PROMOTION_TAG" ]]
[[ "$(append_promotion_tag "$a,$(printf '%s' "$PROMOTION_TAG" | tr '[:lower:]' '[:upper:]')")" == "$a,$PROMOTION_TAG" ]]
! append_promotion_tag "$a,$a"
! append_promotion_tag invalid
pool=''
for ((i=1; i<=100; i++)); do
  printf -v tag '%032x' "$i"
  pool+="${pool:+,}$tag"
done
full="$(append_promotion_tag "$pool")"
[[ "$full" == "$pool,$PROMOTION_TAG" ]]
[[ "$(append_promotion_tag "$full")" == "$full" ]]
! append_promotion_tag "$pool,$a"
for mode in sequence random; do
  GROUP_COUNT=1 GROUP_USERS=(navo) GROUP_SECRETS=(11111111111111111111111111111111)
  GROUP_TAGS=("$a") ROT_MODES=("$mode") ROT_POOLS=("$a") ROT_MINUTES=(30) ROT_NEXT=(0)
  apply_promotion_tags
  validate_groups
  [[ "${ROT_POOLS[0]}" == "$a,$PROMOTION_TAG" && "${ROT_MODES[0]}" == "$mode" ]]
  rotation_enabled
  [[ "$(next_rotation_tag "$mode" "$a" "${ROT_POOLS[0]}")" == "$PROMOTION_TAG" ]]
  [[ "$(next_rotation_tag "$mode" "$PROMOTION_TAG" "${ROT_POOLS[0]}")" == "$a" ]]
  ROT_POOLS=("$full") GROUP_TAGS=("$PROMOTION_TAG")
  validate_groups || exit 1
  GROUP_TAGS=("$a") ROT_POOLS=("$a,$PROMOTION_TAG")
  before="${ROT_NEXT[0]}"
  apply_promotion_tags
  [[ "${ROT_POOLS[0]}" == "$a,$PROMOTION_TAG" && "${ROT_NEXT[0]}" == "$before" ]]
done
for current in '' 00000000000000000000000000000000 "$a" "$PROMOTION_TAG"; do
  GROUP_TAGS=("$current") ROT_MODES=(fixed) ROT_POOLS=('') ROT_NEXT=(0)
  apply_promotion_tags
  validate_groups
  if [[ "$current" == "$a" ]]; then
    [[ "${GROUP_TAGS[0]}" == "$a" && "${ROT_POOLS[0]}" == "$a,$PROMOTION_TAG" ]]
    rotation_enabled
  else
    [[ "${GROUP_TAGS[0]}" == "$PROMOTION_TAG" && "${ROT_POOLS[0]}" == "$PROMOTION_TAG" && "${ROT_NEXT[0]}" == 0 ]]
    ! rotation_enabled
  fi
done
printf 'ok - append, deduplication, limits, both modes, fixed and blank groups\n'
