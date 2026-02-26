#!/usr/bin/env bash

STATE_FILE_DEFAULT="/root/.3x-ui-install.state"
INSTALL_STATE_FILE="${INSTALL_STATE_FILE:-$STATE_FILE_DEFAULT}"
declare -A STATE_VALUES=()

STATE_TRACKED_KEYS=(
  INSTALL_MODE ENDPOINT_MODE DOMAIN EMAIL OPEN_TCP_PORTS OPEN_UDP_PORTS SSH_PORT EXPOSE_PANEL_PUBLIC
  NEW_USER NEW_PASS PANEL_ADMIN_USER PANEL_ADMIN_PASS PANEL_CURRENT_USER PANEL_CURRENT_PASS 
  PANEL_RESET_MODE CERT_STRATEGY CLIENT_PUBLIC_ENDPOINT
  INSTALL_XUI INSTALL_OPENVPN INSTALL_OPENCONNECT INSTALL_AMNEZIA
  AUTO_CREATE_INBOUND VPN_USER VPN_PASS
)

STATE_SECRET_KEYS=(
  NEW_PASS PANEL_CURRENT_PASS PANEL_CURRENT_2FA_CODE PANEL_ADMIN_PASS PANEL_2FA_TOKEN VPN_PASS
)

state_key_is_tracked() {
  local key="$1"
  local candidate=""
  for candidate in "${STATE_TRACKED_KEYS[@]}"; do
    [[ "$candidate" == "$key" ]] && return 0
  done
  return 1
}

state_key_is_secret() {
  local key="$1"
  local candidate=""
  for candidate in "${STATE_SECRET_KEYS[@]}"; do
    [[ "$candidate" == "$key" ]] && return 0
  done
  return 1
}

load_install_state() {
  local state_file="$INSTALL_STATE_FILE"
  local line=""
  local key=""
  local encoded=""
  local decoded=""
  local loaded_count=0

  if [[ ! -f "$state_file" ]]; then
    return 0
  fi
  
  # Check security (root owned, 600) - only if we are on Linux
  if [[ "$(uname)" == "Linux" ]]; then
     local owner_uid
     owner_uid="$(stat -c '%u' "$state_file" 2>/dev/null || true)"
     if [[ "$owner_uid" != "0" ]]; then
        warn "State load: ignored insecure file ${state_file} (not owned by root)"
        return 0
     fi
  fi

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -n "$line" ]] || continue
    [[ "$line" == \#* ]] && continue
    [[ "$line" == *=* ]] || continue
    key="${line%%=*}"
    encoded="${line#*=}"
    [[ "$key" =~ ^[A-Z0-9_]+$ ]] || continue
    state_key_is_tracked "$key" || continue
    if decoded="$(printf '%s' "$encoded" | base64 --decode 2>/dev/null)"; then
      STATE_VALUES["$key"]="$decoded"
      loaded_count=$((loaded_count + 1))
    fi
  done < "$state_file"

  log "State load: restored ${loaded_count} key(s) from ${state_file}"
  return 0
}

save_install_state() {
  local include_secrets="${1:-true}"
  local state_file="$INSTALL_STATE_FILE"
  local state_dir=""
  local tmp_file=""
  local key=""
  local value=""
  local encoded=""
  local saved_count=0

  state_dir="$(dirname "$state_file")"
  mkdir -p "$state_dir"

  tmp_file="$(mktemp /tmp/3xui-state.XXXXXX 2>/dev/null || true)"
  if [[ -z "$tmp_file" ]]; then
    return 0
  fi
  chmod 600 "$tmp_file" 2>/dev/null || true

  for key in "${STATE_TRACKED_KEYS[@]}"; do
    if [[ "$include_secrets" != "true" ]] && state_key_is_secret "$key"; then
      continue
    fi
    value="${!key-}"
    if [[ -z "$value" && -n "${STATE_VALUES[$key]+x}" ]]; then
        value="${STATE_VALUES[$key]}"
    fi
    encoded="$(printf '%s' "$value" | base64 | tr -d '
')"
    printf '%s=%s
' "$key" "$encoded" >> "$tmp_file"
    saved_count=$((saved_count + 1))
  done

  mv "$tmp_file" "$state_file"
  chmod 600 "$state_file"
  return 0
}

resolve_var() {
  local key="$1"
  local default_value="$2"

  if [[ -n "${!key+x}" && -n "${!key-}" ]]; then
    return 0
  fi
  if [[ -n "${STATE_VALUES[$key]+x}" ]]; then
    printf -v "$key" '%s' "${STATE_VALUES[$key]}"
    return 0
  fi
  printf -v "$key" '%s' "$default_value"
}
