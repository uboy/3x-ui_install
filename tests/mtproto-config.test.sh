#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  echo "FAILED: $1" >&2
  exit 1
}

assert_not_contains() {
  local pattern="$1"
  local file="$2"
  grep -Eq "$pattern" "$file" && fail "pattern '$pattern' unexpectedly found in $file"
  return 0
}

assert_contains() {
  local pattern="$1"
  local file="$2"
  grep -Eq "$pattern" "$file" || fail "pattern '$pattern' not found in $file"
}

# --- Regression guards: fabricated/unsafe behavior must not come back ---

assert_not_contains 'allow-skip-dh' "${ROOT_DIR}/modules/mtproto.sh"
assert_not_contains 'nat-info' "${ROOT_DIR}/modules/mtproto.sh"
assert_not_contains 'PORT_MTPROXY:-443' "${ROOT_DIR}/modules/mtproto.sh"
assert_not_contains 'PORT_MTPROXY:-443' "${ROOT_DIR}/install.sh"
assert_not_contains 'PORT_MTPROXY:-443' "${ROOT_DIR}/lib/ui.sh"
assert_not_contains '"mtg\|mtproxy"' "${ROOT_DIR}/lib/ui.sh"

# --- Regression guards: required fixes must stay in place ---

assert_contains 'resolve_var PORT_MTPROXY *"8443"' "${ROOT_DIR}/install.sh"
assert_contains 'resolve_var MTPROXY_DOMAIN' "${ROOT_DIR}/install.sh"
assert_contains 'CAP_NET_BIND_SERVICE' "${ROOT_DIR}/modules/mtproto.sh"
assert_contains 'ui_get_mtproto_domain' "${ROOT_DIR}/install.sh"
assert_contains 'ui_get_mtproto_domain\(\)' "${ROOT_DIR}/lib/ui.sh"
assert_contains 'pick_free_port_from_candidates' "${ROOT_DIR}/lib/utils.sh"
assert_contains 'pick_free_port_from_candidates' "${ROOT_DIR}/install.sh"
assert_contains 'hex_decode_ascii' "${ROOT_DIR}/lib/utils.sh"
assert_contains 'teleproxy' "${ROOT_DIR}/lib/ui.sh"

# --- Unit tests for the pure helpers in lib/utils.sh ---

# Provide the small set of functions utils.sh's own definitions don't need
# but that would otherwise be undefined when sourcing it standalone.
log() { :; }
warn() { :; }
error() { :; }

source "${ROOT_DIR}/lib/utils.sh"

# hex_decode_ascii round-trips through the same od encoding mtproto.sh uses.
_encoded=$(printf '%s' "www.google.com" | od -An -tx1 | tr -d ' \n')
_decoded=$(hex_decode_ascii "$_encoded")
[[ "$_decoded" == "www.google.com" ]] || fail "hex_decode_ascii round-trip mismatch: got '$_decoded'"

hex_decode_ascii "abc" >/dev/null 2>&1 && fail "hex_decode_ascii accepted odd-length input"

# pick_free_port_from_candidates: skips used ports and busy ports, returns the
# first candidate that is both unused and free.
check_port_free() { [[ "$1" != "9443" ]]; }  # simulate 9443 already listening
declare -A USED_PORTS=([2083]="SomeOtherService")

_picked=$(pick_free_port_from_candidates USED_PORTS 9443 2083 2087 2096)
[[ "$_picked" == "2087" ]] || fail "pick_free_port_from_candidates picked '$_picked', expected 2087"

if pick_free_port_from_candidates USED_PORTS 9443 2083 >/dev/null; then
  fail "pick_free_port_from_candidates should have failed when no candidate is free"
fi

echo "MTProto config checks passed."
