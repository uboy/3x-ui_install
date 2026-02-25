#!/usr/bin/env bash
set -Eeuo pipefail

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
APPLIED_STEPS=()
FAIL_REASON=""
STATE_FILE_DEFAULT="/root/.3x-ui-install.state"
INSTALL_STATE_FILE="${INSTALL_STATE_FILE:-$STATE_FILE_DEFAULT}"
STATE_KEEP_SECRETS_ON_SUCCESS="${STATE_KEEP_SECRETS_ON_SUCCESS:-true}"
STATE_TRACKED_KEYS=(
  DOMAIN EMAIL OPEN_TCP_PORTS OPEN_UDP_PORTS SSH_PORT EXPOSE_PANEL_PUBLIC
  NEW_USER NEW_PASS PANEL_CURRENT_USER PANEL_CURRENT_PASS PANEL_CURRENT_2FA_CODE
  PANEL_ADMIN_USER PANEL_ADMIN_PASS ENABLE_PANEL_2FA AUTO_CREATE_INBOUND
  INBOUND_PORT INBOUND_REMARK INBOUND_CLIENT_EMAIL INBOUND_SNI PANEL_2FA_TOKEN
  PANEL_RESET_MODE PANEL_RESET_ACTION PANEL_RESET_RESULT PANEL_FACTORY_BACKUP_PATH
)
STATE_SECRET_KEYS=(
  NEW_PASS PANEL_CURRENT_PASS PANEL_CURRENT_2FA_CODE PANEL_ADMIN_PASS PANEL_2FA_TOKEN
)
declare -A STATE_VALUES=()

mark_step_applied() {
  local step="$1"
  local existing=""
  [[ -n "$step" ]] || return 0
  for existing in "${APPLIED_STEPS[@]}"; do
    [[ "$existing" == "$step" ]] && return 0
  done
  APPLIED_STEPS+=("$step")
}

report_failure_progress() {
  local rc="${1:-1}"
  local joined=""
  local step=""

  printf '\nINSTALL FAILED (exit code %s)\n' "$rc" >&2
  if [[ -n "$FAIL_REASON" ]]; then
    printf 'Failure reason: %s\n' "$FAIL_REASON" >&2
  fi

  if (( ${#APPLIED_STEPS[@]} > 0 )); then
    for step in "${APPLIED_STEPS[@]}"; do
      if [[ -n "$joined" ]]; then
        joined+=", "
      fi
      joined+="$step"
    done
    printf 'Applied steps: %s\n' "$joined" >&2
  else
    printf 'Applied steps: none\n' >&2
  fi
}

die() {
  local message="$*"
  [[ -n "$message" ]] || message="Unknown error."
  [[ -n "$FAIL_REASON" ]] || FAIL_REASON="$message"
  printf 'ERROR: %s\n' "$message" >&2
  exit 1
}

read_name_regex() {
  local cfg="/etc/adduser.conf"
  local line=""
  local regex=""

  if [[ -r "$cfg" ]]; then
    line="$(grep -E '^[[:space:]]*NAME_REGEX[[:space:]]*=' "$cfg" | tail -n1 || true)"
    regex="${line#*=}"
    regex="${regex#"${regex%%[![:space:]]*}"}"
    regex="${regex%"${regex##*[![:space:]]}"}"
    regex="${regex%\"}"
    regex="${regex#\"}"
  fi

  [[ -n "$regex" ]] || regex='^[a-z][-a-z0-9_]*$'
  printf '%s\n' "$regex"
}

is_valid_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1 && p <= 65535 ))
}

array_contains() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

normalize_bool_choice() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    true|yes|y|1) printf 'true\n' ;;
    false|no|n|0|'') printf 'false\n' ;;
    *) return 1 ;;
  esac
}

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

# Priority: env > state > default
resolve_var_from_env_state_default() {
  local key="$1"
  local default_value="$2"

  if [[ -n "${!key+x}" ]]; then
    return 0
  fi
  if [[ -n "${STATE_VALUES[$key]+x}" ]]; then
    printf -v "$key" '%s' "${STATE_VALUES[$key]}"
    return 0
  fi
  printf -v "$key" '%s' "$default_value"
}

state_file_is_secure() {
  local state_file="$1"
  local owner_uid=""
  local perm_octal=""
  local perm_masked=0

  [[ -f "$state_file" ]] || return 1
  [[ ! -L "$state_file" ]] || return 1

  owner_uid="$(stat -c '%u' "$state_file" 2>/dev/null || true)"
  perm_octal="$(stat -c '%a' "$state_file" 2>/dev/null || true)"
  [[ "$owner_uid" == "0" ]] || return 1
  [[ "$perm_octal" =~ ^[0-7]{3,4}$ ]] || return 1

  perm_masked=$(( 8#$perm_octal & 077 ))
  (( perm_masked == 0 ))
}

load_install_state() {
  local state_file="$INSTALL_STATE_FILE"
  local line=""
  local key=""
  local encoded=""
  local decoded=""
  local loaded_count=0

  if [[ ! -f "$state_file" ]]; then
    log "State load: no file at ${state_file}"
    return 0
  fi
  if [[ ! -r "$state_file" ]]; then
    log "State load: file is not readable (${state_file})"
    return 0
  fi
  if ! state_file_is_secure "$state_file"; then
    log "State load: ignored insecure file ${state_file} (expected root-owned regular file, mode 600/400)."
    return 0
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
  local mode="${2:-checkpoint}"
  local state_file="$INSTALL_STATE_FILE"
  local state_dir=""
  local tmp_file=""
  local key=""
  local value=""
  local encoded=""
  local saved_count=0

  state_dir="$(dirname "$state_file")"
  if ! install -d -m 700 "$state_dir" 2>/dev/null; then
    log "State save: skipped (cannot create ${state_dir})"
    return 0
  fi

  tmp_file="$(mktemp /tmp/3xui-state.XXXXXX 2>/dev/null || true)"
  if [[ -z "$tmp_file" ]]; then
    log "State save: skipped (failed to create temporary file)"
    return 0
  fi
  chmod 600 "$tmp_file" 2>/dev/null || true

  for key in "${STATE_TRACKED_KEYS[@]}"; do
    if [[ "$include_secrets" != "true" ]] && state_key_is_secret "$key"; then
      continue
    fi
    value="${!key-}"
    encoded="$(printf '%s' "$value" | base64 | tr -d '\n')"
    if ! printf '%s=%s\n' "$key" "$encoded" >> "$tmp_file"; then
      rm -f "$tmp_file"
      log "State save: skipped (failed writing temporary file)"
      return 0
    fi
    saved_count=$((saved_count + 1))
  done

  if install -m 600 "$tmp_file" "$state_file" 2>/dev/null; then
    if [[ "$include_secrets" == "true" ]]; then
      log "State save: ${mode} (${saved_count} key(s)) -> ${state_file}"
    else
      log "State scrub: removed secret keys (${saved_count} key(s)) -> ${state_file}"
    fi
  else
    log "State save: failed to write ${state_file}"
  fi

  rm -f "$tmp_file"
  return 0
}

save_state_checkpoint() {
  save_install_state "true" "checkpoint"
}

ensure_passwordless_sudo() {
  local username="$1"
  local sudoers_dir="/etc/sudoers.d"
  local sudoers_file="${sudoers_dir}/90-3xui-${username}"
  local tmp_file=""

  install -d -m 755 "$sudoers_dir"
  tmp_file="$(mktemp /tmp/3xui-sudoers.XXXXXX)"
  printf '%s ALL=(ALL:ALL) NOPASSWD:ALL\n' "$username" > "$tmp_file"
  chmod 440 "$tmp_file"
  visudo -cf "$tmp_file" >/dev/null || {
    rm -f "$tmp_file"
    die "Generated sudoers drop-in for ${username} failed validation."
  }
  install -m 440 "$tmp_file" "$sudoers_file"
  rm -f "$tmp_file"
  visudo -cf /etc/sudoers >/dev/null || die "sudoers validation failed after updating ${sudoers_file}."
}

generate_strong_secret() {
  openssl rand -base64 48 | tr -d '\n' | tr -d '/+=' | cut -c1-28
}

user_has_usable_password() {
  local username="$1"
  local status=""
  local shadow_hash=""

  status="$(passwd -S "$username" 2>/dev/null | awk '{print $2}' || true)"
  case "$status" in
    P|PS) return 0 ;;
  esac

  shadow_hash="$(getent shadow "$username" | cut -d: -f2 || true)"
  case "$shadow_hash" in
    ''|'!'|'!!'|'*') return 1 ;;
    '!'*|'*') return 1 ;;
  esac

  return 0
}

generate_panel_username() {
  printf 'admin_%s\n' "$(tr -dc 'a-z0-9' </dev/urandom | head -c 10)"
}

generate_base32_token() {
  head -c 32 /dev/urandom | base32 | tr -d '=\n' | cut -c1-32
}

generate_uuid() {
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    cat /proc/sys/kernel/random/uuid
    return 0
  fi
  openssl rand -hex 16 | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/'
}

generate_sub_id() {
  tr -dc 'a-z0-9' </dev/urandom | head -c 16
}

normalize_base_path() {
  local p="${1:-/}"
  [[ -n "$p" ]] || p="/"
  [[ "$p" == /* ]] || p="/$p"
  [[ "$p" == */ ]] || p="${p}/"
  while [[ "$p" == *"//"* ]]; do
    p="${p//\/\//\/}"
  done
  printf '%s\n' "$p"
}

panel_write_secret_file() {
  local value="$1"
  local tmp_file=""
  tmp_file="$(mktemp /tmp/3xui-secret.XXXXXX)"
  chmod 600 "$tmp_file"
  printf '%s' "$value" > "$tmp_file"
  PANEL_TEMP_FILES+=("$tmp_file")
  printf '%s\n' "$tmp_file"
}

panel_wait_ready() {
  local i
  for (( i = 0; i < 60; i++ )); do
    if curl -ksS --max-time 5 "http://127.0.0.1:${PANEL_PORT}/" >/dev/null 2>&1 || \
       curl -ksS --max-time 5 "https://127.0.0.1:${PANEL_PORT}/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

debug_permit_root_login_sources() {
  local cfg=""
  local source_line=""
  local -a cfg_files=(/etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf)

  log "Debug: effective PermitRootLogin from sshd -T"
  /usr/sbin/sshd -T 2>/dev/null | grep -i '^permitrootlogin ' || true

  log "Debug: conflicting PermitRootLogin directives in source files"
  for cfg in "${cfg_files[@]}"; do
    [[ -f "$cfg" ]] || continue
    while IFS= read -r source_line; do
      printf '  %s:%s\n' "$cfg" "$source_line" >&2
    done < <(awk '
      match($0,/^[[:space:]]*PermitRootLogin[[:space:]]+/) {
        value=tolower($2)
        if (value != "no") print NR ":" $0
      }' "$cfg")
  done
}

validate_sshd_root_login_no() {
  local context="$1"
  local label=""

  if /usr/sbin/sshd -T | grep -i '^permitrootlogin no$' >/dev/null; then
    return 0
  fi

  [[ -n "$context" ]] && label=" (${context})"
  log "SSH hardening validation failed${label}; collecting PermitRootLogin debug details"
  debug_permit_root_login_sources
  die "SSH hardening validation failed${label}: PermitRootLogin is not 'no'."
}

ensure_sshd_dropin_include() {
  if grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf([[:space:]]|$)' /etc/ssh/sshd_config; then
    return 0
  fi
  log "Adding missing Include /etc/ssh/sshd_config.d/*.conf to /etc/ssh/sshd_config"
  printf '\nInclude /etc/ssh/sshd_config.d/*.conf\n' >> /etc/ssh/sshd_config
}

panel_login() {
  local username="$1"
  local password="$2"
  local two_factor_code="${3:-}"
  local response=""
  local password_file=""
  local two_factor_file=""

  password_file="$(panel_write_secret_file "$password")"

  : > "$PANEL_COOKIE_FILE"
  if [[ -n "$two_factor_code" ]]; then
    two_factor_file="$(panel_write_secret_file "$two_factor_code")"
    response="$(curl -ksS --max-time 10 \
      -c "$PANEL_COOKIE_FILE" -b "$PANEL_COOKIE_FILE" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode "username=${username}" \
      --data-urlencode "password@${password_file}" \
      --data-urlencode "twoFactorCode@${two_factor_file}" \
      "${PANEL_API_ORIGIN}${PANEL_BASE_PATH}login" || true)"
  else
    response="$(curl -ksS --max-time 10 \
      -c "$PANEL_COOKIE_FILE" -b "$PANEL_COOKIE_FILE" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode "username=${username}" \
      --data-urlencode "password@${password_file}" \
      "${PANEL_API_ORIGIN}${PANEL_BASE_PATH}login" || true)"
  fi

  [[ "$response" == *'"success":true'* ]]
}

panel_detect_access() {
  local cli_base=""
  local scheme=""
  local origin=""
  local response=""
  local base=""
  local redirect_loc=""
  local -a candidates=("/")
  local -a uniq_candidates=()

  if docker exec "$CONTAINER_NAME" sh -lc 'command -v x-ui >/dev/null 2>&1'; then
    cli_base="$(docker exec "$CONTAINER_NAME" sh -lc "x-ui setting -show 2>/dev/null | awk -F': ' '/^webBasePath:/ {print \$2; exit}'" || true)"
    if [[ -n "${cli_base//[[:space:]]/}" ]]; then
      candidates+=("$(normalize_base_path "$cli_base")")
    fi
  fi

  for scheme in http https; do
    origin="${scheme}://127.0.0.1:${PANEL_PORT}"
    redirect_loc="$(curl -ksSI --max-time 6 "${origin}/" | awk 'BEGIN{IGNORECASE=1} /^Location:/ {print $2; exit}' | tr -d '\r' || true)"
    if [[ -n "$redirect_loc" && "$redirect_loc" == /* ]]; then
      redirect_loc="${redirect_loc%%\?*}"
      redirect_loc="${redirect_loc%%#*}"
      redirect_loc="${redirect_loc%%panel*}"
      candidates+=("$(normalize_base_path "$redirect_loc")")
    fi

    uniq_candidates=()
    for base in "${candidates[@]}"; do
      base="$(normalize_base_path "$base")"
      if ! array_contains "$base" "${uniq_candidates[@]}"; then
        uniq_candidates+=("$base")
      fi
    done

    for base in "${uniq_candidates[@]}"; do
      response="$(curl -ksS --max-time 8 \
        -c "$PANEL_COOKIE_FILE" -b "$PANEL_COOKIE_FILE" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode "username=__probe__" \
        --data-urlencode "password=__probe__" \
        "${origin}${base}login" || true)"
      if [[ "$response" == *'"success":'* && "$response" == *'"msg":'* ]]; then
        PANEL_API_ORIGIN="$origin"
        PANEL_BASE_PATH="$base"
        return 0
      fi
    done
  done

  return 1
}

panel_apply_credentials() {
  local rc=0

  PANEL_RESET_ACTION="none"
  PANEL_RESET_RESULT="not-attempted"
  PANEL_FACTORY_BACKUP_PATH=""

  if panel_apply_credentials_api_first; then
    return 0
  else
    rc=$?
  fi
  if (( rc != 1 && rc != 2 )); then
    die "Panel credentials flow failed unexpectedly (rc=${rc})."
  fi

  if ! panel_recover_credentials_once; then
    if [[ "$PANEL_RESET_MODE" == "none" ]]; then
      if (( rc == 1 )); then
        die "Failed to update panel credentials via API fallback. Set panel recovery mode to 2fa or factory and retry."
      fi
      die "Failed to apply panel credentials via API. Provide valid current panel credentials (and current 2FA code if enabled), or set panel recovery mode to 2fa/factory."
    fi
    die "Panel credential recovery failed (mode=${PANEL_RESET_MODE}, action=${PANEL_RESET_ACTION}, result=${PANEL_RESET_RESULT})."
  fi

  if panel_apply_credentials_api_first; then
    return 0
  else
    rc=$?
  fi
  if (( rc == 2 )); then
    die "Panel credentials recovery action completed but API login still failed (mode=${PANEL_RESET_MODE}, action=${PANEL_RESET_ACTION})."
  fi
  die "Failed to update panel credentials via API fallback."
}

panel_apply_credentials_api_first() {
  local method="none"
  local response=""
  local old_password_file=""
  local new_password_file=""
  local api_required="false"

  if panel_login "$PANEL_ADMIN_USER" "$PANEL_ADMIN_PASS" "$PANEL_CURRENT_2FA_CODE"; then
    PANEL_CREDS_METHOD="already-set"
    PANEL_API_LOGIN_AVAILABLE="true"
    return 0
  fi

  if panel_login "$PANEL_CURRENT_USER" "$PANEL_CURRENT_PASS" "$PANEL_CURRENT_2FA_CODE"; then
    old_password_file="$(panel_write_secret_file "$PANEL_CURRENT_PASS")"
    new_password_file="$(panel_write_secret_file "$PANEL_ADMIN_PASS")"
    response="$(curl -ksS --max-time 10 \
      -c "$PANEL_COOKIE_FILE" -b "$PANEL_COOKIE_FILE" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode "oldUsername=${PANEL_CURRENT_USER}" \
      --data-urlencode "oldPassword@${old_password_file}" \
      --data-urlencode "newUsername=${PANEL_ADMIN_USER}" \
      --data-urlencode "newPassword@${new_password_file}" \
      "${PANEL_API_ORIGIN}${PANEL_BASE_PATH}panel/setting/updateUser" || true)"
    if [[ "$response" != *'"success":true'* ]]; then
      log "Panel updateUser API did not return success. Response: ${response}"
      return 1
    fi
    method="api"
  fi

  if [[ "$AUTO_CREATE_INBOUND" == "true" || "$ENABLE_PANEL_2FA" == "true" ]]; then
    api_required="true"
  fi

  if panel_login "$PANEL_ADMIN_USER" "$PANEL_ADMIN_PASS" "$PANEL_CURRENT_2FA_CODE"; then
    PANEL_API_LOGIN_AVAILABLE="true"
  elif [[ "$method" != "none" && "$api_required" != "true" ]]; then
    PANEL_API_LOGIN_AVAILABLE="false"
  else
    return 2
  fi

  case "$method" in
    api) PANEL_CREDS_METHOD="api" ;;
    *) PANEL_CREDS_METHOD="unknown" ;;
  esac
}

panel_reset_two_factor_cli() {
  if ! docker exec "$CONTAINER_NAME" sh -lc 'command -v x-ui >/dev/null 2>&1'; then
    return 1
  fi
  if ! docker exec "$CONTAINER_NAME" x-ui setting -resetTwoFactor >/dev/null 2>&1; then
    return 1
  fi
  PANEL_CURRENT_2FA_CODE=""
  PANEL_2FA_RESET_FOR_API="true"
  PANEL_2FA_EFFECTIVE="false"
  PANEL_2FA_TOKEN=""
  return 0
}

panel_factory_reset_with_backup() {
  local timestamp=""
  local backup_dir=""
  local backup_path=""
  local compose_file=""

  timestamp="$(date '+%Y%m%d-%H%M%S')"
  backup_dir="${PANEL_DIR}/backup"
  backup_path="${backup_dir}/db-${timestamp}.tar.gz"
  compose_file="${PANEL_DIR}/docker-compose.yml"

  install -d -m 700 "$backup_dir" || return 1
  [[ -d "${PANEL_DIR}/db" ]] || return 1
  tar -C "$PANEL_DIR" -czf "$backup_path" db || return 1
  chmod 600 "$backup_path" 2>/dev/null || true
  PANEL_FACTORY_BACKUP_PATH="$backup_path"

  docker compose -f "$compose_file" down || return 1
  rm -rf "${PANEL_DIR}/db"
  install -d -m 700 "${PANEL_DIR}/db" || return 1
  docker compose -f "$compose_file" up -d || return 1
  panel_wait_ready || return 1
  panel_detect_access || return 1

  PANEL_CURRENT_USER="admin"
  PANEL_CURRENT_PASS="admin"
  PANEL_CURRENT_2FA_CODE=""
  PANEL_2FA_EFFECTIVE="false"
  PANEL_2FA_TOKEN=""
  return 0
}

panel_recover_credentials_once() {
  case "$PANEL_RESET_MODE" in
    none)
      PANEL_RESET_ACTION="none"
      PANEL_RESET_RESULT="skipped"
      return 1
      ;;
    2fa)
      PANEL_RESET_ACTION="cli-reset-two-factor"
      if panel_reset_two_factor_cli; then
        PANEL_RESET_RESULT="success"
        return 0
      fi
      PANEL_RESET_RESULT="failed"
      return 1
      ;;
    factory)
      PANEL_RESET_ACTION="factory-reset"
      if panel_factory_reset_with_backup; then
        PANEL_RESET_RESULT="success"
        return 0
      fi
      PANEL_RESET_RESULT="failed"
      return 1
      ;;
    *)
      PANEL_RESET_ACTION="invalid-mode"
      PANEL_RESET_RESULT="failed"
      return 1
      ;;
  esac
}

panel_enable_two_factor() {
  local settings_response=""
  local updated_json=""
  local update_response=""

  settings_response="$(curl -ksS --max-time 10 \
    -c "$PANEL_COOKIE_FILE" -b "$PANEL_COOKIE_FILE" \
    -X POST \
    "${PANEL_API_ORIGIN}${PANEL_BASE_PATH}panel/setting/all" || true)"
  [[ "$settings_response" == *'"success":true'* ]] || die "Failed to fetch panel settings for 2FA update."

  PANEL_2FA_TOKEN="$(generate_base32_token)"
  updated_json="$(python3 -c 'import json,sys
payload=json.load(sys.stdin)
obj=payload.get("obj")
if not isinstance(obj,dict):
    raise SystemExit(1)
current_enabled=bool(obj.get("twoFactorEnable"))
current_token=str(obj.get("twoFactorToken") or "")
if current_enabled and current_token:
    print("SKIP:"+current_token)
    raise SystemExit(0)
obj["twoFactorEnable"]=True
obj["twoFactorToken"]=sys.argv[1]
print("UPDATE:"+json.dumps(obj,separators=(",",":")))' "$PANEL_2FA_TOKEN" <<< "$settings_response")"

  case "$updated_json" in
    SKIP:*)
      PANEL_2FA_TOKEN="${updated_json#SKIP:}"
      PANEL_2FA_EFFECTIVE="true"
      return 0
      ;;
    UPDATE:*)
      updated_json="${updated_json#UPDATE:}"
      ;;
    *)
      die "Unable to prepare 2FA settings payload."
      ;;
  esac

  update_response="$(curl -ksS --max-time 10 \
    -c "$PANEL_COOKIE_FILE" -b "$PANEL_COOKIE_FILE" \
    -H 'Content-Type: application/json' \
    -X POST \
    --data "$updated_json" \
    "${PANEL_API_ORIGIN}${PANEL_BASE_PATH}panel/setting/update" || true)"
  [[ "$update_response" == *'"success":true'* ]] || die "Failed to enable panel 2FA via API."

  PANEL_2FA_EFFECTIVE="true"
}

panel_ensure_vless_inbound() {
  local list_response=""
  local add_response=""
  local parse_result=""
  local existing_id=""
  local existing_client_id=""
  local existing_client_email=""
  local -a parsed_lines=()
  local settings_json=""
  local stream_json=""
  local sniffing_json='{"enabled":true,"destOverride":["http","tls","quic"]}'
  local cert_file="/root/cert/live/${DOMAIN}/fullchain.pem"
  local key_file="/root/cert/live/${DOMAIN}/privkey.pem"

  list_response="$(curl -ksS --max-time 10 \
    -c "$PANEL_COOKIE_FILE" -b "$PANEL_COOKIE_FILE" \
    "${PANEL_API_ORIGIN}${PANEL_BASE_PATH}panel/api/inbounds/list" || true)"
  [[ "$list_response" == *'"success":true'* ]] || die "Failed to query existing inbounds."

  parse_result="$(python3 -c 'import json,sys
payload=json.load(sys.stdin)
items=payload.get("obj")
target_port=int(sys.argv[1])
if not isinstance(items,list):
    raise SystemExit(0)
for item in items:
    try:
        port=int(item.get("port",0))
    except Exception:
        continue
    protocol=str(item.get("protocol","")).lower()
    if port != target_port or protocol != "vless":
        continue
    settings=item.get("settings")
    if isinstance(settings,str):
        try:
            settings=json.loads(settings)
        except Exception:
            settings={}
    clients=settings.get("clients") if isinstance(settings,dict) else []
    first=clients[0] if clients else {}
    print(str(item.get("id","")))
    print(str(first.get("id","")))
    print(str(first.get("email","")))
    raise SystemExit(0)' "$INBOUND_PORT" <<< "$list_response")"

  if [[ -n "$parse_result" ]]; then
    mapfile -t parsed_lines <<< "$parse_result"
    existing_id="${parsed_lines[0]:-}"
    existing_client_id="${parsed_lines[1]:-}"
    existing_client_email="${parsed_lines[2]:-}"
    INBOUND_STATUS="existing"
    INBOUND_ID="$existing_id"
    [[ -n "$existing_client_id" ]] && INBOUND_CLIENT_ID="$existing_client_id"
    [[ -n "$existing_client_email" ]] && INBOUND_CLIENT_EMAIL="$existing_client_email"
    return 0
  fi

  [[ -n "$INBOUND_CLIENT_ID" ]] || INBOUND_CLIENT_ID="$(generate_uuid)"
  [[ -n "$INBOUND_CLIENT_SUBID" ]] || INBOUND_CLIENT_SUBID="$(generate_sub_id)"

  settings_json="$(python3 -c 'import json,sys
payload={"clients":[{"id":sys.argv[1],"flow":"","email":sys.argv[2],"limitIp":0,"totalGB":0,"expiryTime":0,"enable":True,"tgId":"","subId":sys.argv[3],"comment":"","reset":0}],"decryption":"none"}
print(json.dumps(payload,separators=(",",":")))' "$INBOUND_CLIENT_ID" "$INBOUND_CLIENT_EMAIL" "$INBOUND_CLIENT_SUBID")"

  stream_json="$(python3 -c 'import json,sys
payload={"network":"tcp","security":"tls","tcpSettings":{"acceptProxyProtocol":False,"header":{"type":"none"}},"tlsSettings":{"serverName":sys.argv[1],"certificates":[{"certificateFile":sys.argv[2],"keyFile":sys.argv[3]}],"alpn":["http/1.1"]}}
print(json.dumps(payload,separators=(",",":")))' "$INBOUND_SNI" "$cert_file" "$key_file")"

  add_response="$(curl -ksS --max-time 12 \
    -c "$PANEL_COOKIE_FILE" -b "$PANEL_COOKIE_FILE" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "up=0" \
    --data-urlencode "down=0" \
    --data-urlencode "total=0" \
    --data-urlencode "remark=${INBOUND_REMARK}" \
    --data-urlencode "enable=true" \
    --data-urlencode "expiryTime=0" \
    --data-urlencode "listen=" \
    --data-urlencode "port=${INBOUND_PORT}" \
    --data-urlencode "protocol=vless" \
    --data-urlencode "settings=${settings_json}" \
    --data-urlencode "streamSettings=${stream_json}" \
    --data-urlencode "sniffing=${sniffing_json}" \
    -X POST \
    "${PANEL_API_ORIGIN}${PANEL_BASE_PATH}panel/api/inbounds/add" || true)"
  [[ "$add_response" == *'"success":true'* ]] || die "Failed to auto-create VLESS+TLS inbound."

  INBOUND_ID="$(python3 -c 'import json,sys
payload=json.load(sys.stdin)
obj=payload.get("obj")
if isinstance(obj,dict):
    print(str(obj.get("id","")))' <<< "$add_response")"
  INBOUND_STATUS="created"
}

cleanup_temp_files() {
  if [[ -n "${PANEL_TEMP_FILES+x}" && "${#PANEL_TEMP_FILES[@]}" -gt 0 ]]; then
    rm -f "${PANEL_TEMP_FILES[@]}"
  fi
  if [[ -n "${PANEL_COOKIE_FILE:-}" ]]; then
    rm -f "$PANEL_COOKIE_FILE"
  fi
}

on_exit() {
  local rc=$?
  if (( rc != 0 )); then
    save_install_state "true" "failure-exit"
  else
    if [[ "$STATE_KEEP_SECRETS_ON_SUCCESS" == "true" ]]; then
      save_install_state "true" "success-exit"
    else
      save_install_state "false" "success-exit"
    fi
  fi
  cleanup_temp_files
  if (( rc != 0 )); then
    report_failure_progress "$rc"
  fi
  trap - EXIT
  exit "$rc"
}

trap on_exit EXIT

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  die "Run as root (sudo)."
fi

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
    die "This installer targets Ubuntu 24.04 (detected: ${ID:-unknown} ${VERSION_ID:-unknown})."
  fi
fi

# Interactive prompts are primary flow. Environment variables remain supported
# for non-interactive automation.

load_install_state

resolve_var_from_env_state_default DOMAIN ""
resolve_var_from_env_state_default EMAIL ""
resolve_var_from_env_state_default OPEN_TCP_PORTS "443"
resolve_var_from_env_state_default OPEN_UDP_PORTS ""
resolve_var_from_env_state_default NEW_USER ""
resolve_var_from_env_state_default NEW_PASS ""
resolve_var_from_env_state_default PANEL_ADMIN_USER ""
resolve_var_from_env_state_default PANEL_ADMIN_PASS ""
resolve_var_from_env_state_default PANEL_CURRENT_USER "admin"
resolve_var_from_env_state_default PANEL_CURRENT_PASS "admin"
resolve_var_from_env_state_default PANEL_CURRENT_2FA_CODE ""
resolve_var_from_env_state_default PANEL_RESET_MODE "none"
PANEL_FACTORY_RESET_CONFIRM="${PANEL_FACTORY_RESET_CONFIRM:-}"
resolve_var_from_env_state_default PANEL_RESET_ACTION "none"
resolve_var_from_env_state_default PANEL_RESET_RESULT "not-attempted"
resolve_var_from_env_state_default PANEL_FACTORY_BACKUP_PATH ""
resolve_var_from_env_state_default ENABLE_PANEL_2FA "false"
resolve_var_from_env_state_default AUTO_CREATE_INBOUND "false"
# Default inbound port is 443 unless INBOUND_PORT is explicitly provided.
resolve_var_from_env_state_default INBOUND_PORT "443"
resolve_var_from_env_state_default INBOUND_REMARK ""
resolve_var_from_env_state_default INBOUND_CLIENT_EMAIL ""
resolve_var_from_env_state_default INBOUND_SNI ""
INBOUND_CLIENT_ID="${INBOUND_CLIENT_ID:-}"
INBOUND_CLIENT_SUBID="${INBOUND_CLIENT_SUBID:-}"
resolve_var_from_env_state_default SSH_PORT "22"
SSH_ALLOW_USERS="${SSH_ALLOW_USERS:-}"
PANEL_DIR="${PANEL_DIR:-/opt/3x-ui}"
IMAGE="${IMAGE:-ghcr.io/mhsanaei/3x-ui:latest}"
CONTAINER_NAME="${CONTAINER_NAME:-3x-ui}"
PANEL_PORT="${PANEL_PORT:-2053}"
SUB_PORT="${SUB_PORT:-2096}"
resolve_var_from_env_state_default EXPOSE_PANEL_PUBLIC "false"
PANEL_API_ORIGIN=""
PANEL_BASE_PATH="/"
PANEL_COOKIE_FILE=""
PANEL_TEMP_FILES=()
PANEL_CREDS_METHOD="not-applied"
PANEL_API_LOGIN_AVAILABLE="false"
PANEL_2FA_TOKEN=""
PANEL_2FA_EFFECTIVE="false"
PANEL_2FA_RESET_FOR_API="false"
PANEL_RESET_ACTION="none"
PANEL_RESET_RESULT="not-attempted"
PANEL_FACTORY_BACKUP_PATH=""
INBOUND_STATUS="not-requested"
INBOUND_ID=""

USER_EXPLICIT=false
if [[ -n "$NEW_USER" ]]; then
  USER_EXPLICIT=true
fi

NAME_REGEX_PROMPT="$(read_name_regex)"
regex_prompt_rc=0
printf 'testuser\n' | grep -Eq -- "$NAME_REGEX_PROMPT" 2>/dev/null || regex_prompt_rc=$?
if [[ "$regex_prompt_rc" -eq 2 ]]; then
  NAME_REGEX_PROMPT='^[a-z][-a-z0-9_]*$'
fi

if [[ -t 0 ]]; then
  log "Collecting interactive setup inputs"

  while :; do
    if [[ -n "$DOMAIN" ]]; then
      read -r -p "Domain (FQDN for this server) [$DOMAIN]: " input
      DOMAIN="${input:-$DOMAIN}"
    else
      read -r -p "Domain (FQDN for this server): " DOMAIN
    fi
    [[ -n "$DOMAIN" && "$DOMAIN" == *.* ]] && break
    printf 'Invalid domain. Enter a valid FQDN.\n' >&2
  done
  save_state_checkpoint

  while :; do
    if [[ -n "$EMAIL" ]]; then
      read -r -p "Email for Let's Encrypt [$EMAIL]: " input
      EMAIL="${input:-$EMAIL}"
    else
      read -r -p "Email for Let's Encrypt: " EMAIL
    fi
    [[ -n "$EMAIL" && "$EMAIL" == *"@"* ]] && break
    printf 'Invalid email. Enter a valid address.\n' >&2
  done
  save_state_checkpoint

  while :; do
    read -r -p "Inbound TCP ports (space/comma separated) [${OPEN_TCP_PORTS}] (default 443, Enter keeps shown value): " input
    OPEN_TCP_PORTS="${input:-$OPEN_TCP_PORTS}"
    OPEN_TCP_PORTS="${OPEN_TCP_PORTS//,/ }"
    [[ -n "${OPEN_TCP_PORTS//[[:space:]]/}" ]] || {
      printf 'At least one TCP port is required.\n' >&2
      continue
    }
    tcp_invalid=""
    for p in $OPEN_TCP_PORTS; do
      if ! is_valid_port "$p"; then
        tcp_invalid="$p"
        break
      fi
    done
    [[ -z "$tcp_invalid" ]] && break
    printf 'Invalid TCP port: %s\n' "$tcp_invalid" >&2
  done
  save_state_checkpoint

  while :; do
    if [[ -n "$OPEN_UDP_PORTS" ]]; then
      read -r -p "Inbound UDP ports (optional, space/comma separated) [$OPEN_UDP_PORTS]: " input
      OPEN_UDP_PORTS="${input:-$OPEN_UDP_PORTS}"
    else
      read -r -p "Inbound UDP ports (optional, space/comma separated): " OPEN_UDP_PORTS
    fi
    OPEN_UDP_PORTS="${OPEN_UDP_PORTS//,/ }"
    udp_invalid=""
    for p in $OPEN_UDP_PORTS; do
      if ! is_valid_port "$p"; then
        udp_invalid="$p"
        break
      fi
    done
    [[ -z "$udp_invalid" ]] && break
    printf 'Invalid UDP port: %s\n' "$udp_invalid" >&2
  done
  save_state_checkpoint

  while :; do
    read -r -p "SSH port [${SSH_PORT}]: " input
    SSH_PORT="${input:-$SSH_PORT}"
    is_valid_port "$SSH_PORT" && break
    printf 'Invalid SSH port. Use 1..65535.\n' >&2
  done
  save_state_checkpoint

  while :; do
    bool_hint="[y/N]"
    [[ "$EXPOSE_PANEL_PUBLIC" == "true" ]] && bool_hint="[Y/n]"
    read -r -p "Expose 3x-ui panel ports publicly? ${bool_hint}: " input
    [[ -n "$input" ]] || input="$EXPOSE_PANEL_PUBLIC"
    EXPOSE_PANEL_PUBLIC="$(normalize_bool_choice "$input")" || {
      printf "Enter yes/y or no/n.\n" >&2
      continue
    }
    break
  done
  save_state_checkpoint

  while :; do
    if [[ -n "$NEW_USER" ]]; then
      read -r -p "SSH username [${NEW_USER}] (Enter keeps, type 'auto' to auto-generate): " input
      if [[ -z "$input" ]]; then
        USER_EXPLICIT=true
        break
      fi
      if [[ "${input,,}" == "auto" ]]; then
        NEW_USER=""
        USER_EXPLICIT=false
        break
      fi
    else
      read -r -p "SSH username (optional, blank = auto-generate): " input
      if [[ -z "$input" ]]; then
        USER_EXPLICIT=false
        break
      fi
    fi
    NEW_USER="$input"
    [[ "$NEW_USER" =~ ^[a-z][-a-z0-9_]{0,31}$ ]] || {
      printf "Username must match ^[a-z][-a-z0-9_]{0,31}$.\n" >&2
      continue
    }
    printf '%s\n' "$NEW_USER" | grep -Eq -- "$NAME_REGEX_PROMPT" || {
      printf "Username does not satisfy adduser NAME_REGEX (%s).\n" "$NAME_REGEX_PROMPT" >&2
      continue
    }
    USER_EXPLICIT=true
    break
  done
  save_state_checkpoint

  read -r -s -p "SSH password (optional; blank keeps existing password, auto-generates when missing/new): " NEW_PASS
  printf '\n'
  save_state_checkpoint

  while :; do
    read -r -p "Current panel username for API fallback [${PANEL_CURRENT_USER}]: " input
    PANEL_CURRENT_USER="${input:-$PANEL_CURRENT_USER}"
    [[ -n "$PANEL_CURRENT_USER" ]] && break
    printf 'Current panel username must not be empty.\n' >&2
  done
  save_state_checkpoint

  if [[ -n "$PANEL_CURRENT_PASS" ]]; then
    read -r -s -p "Current panel password for API fallback (blank keeps existing value): " input
    if [[ -n "$input" ]]; then
      PANEL_CURRENT_PASS="$input"
    fi
  else
    read -r -s -p "Current panel password for API fallback (optional): " PANEL_CURRENT_PASS
  fi
  printf '\n'
  save_state_checkpoint

  if [[ -n "$PANEL_CURRENT_2FA_CODE" ]]; then
    read -r -p "Current panel 2FA code for API fallback (optional, blank keeps existing value): " input
    if [[ -n "$input" ]]; then
      PANEL_CURRENT_2FA_CODE="$input"
    fi
  else
    read -r -p "Current panel 2FA code for API fallback (optional): " PANEL_CURRENT_2FA_CODE
  fi
  save_state_checkpoint

  while :; do
    read -r -p "Panel credential recovery mode [${PANEL_RESET_MODE}] (none/2fa/factory): " input
    PANEL_RESET_MODE="${input:-$PANEL_RESET_MODE}"
    PANEL_RESET_MODE="$(printf '%s' "$PANEL_RESET_MODE" | tr '[:upper:]' '[:lower:]')"
    case "$PANEL_RESET_MODE" in
      none|2fa)
        break
        ;;
      factory)
        printf 'WARNING: factory mode will stop 3x-ui, recreate panel DB, and reset panel config to defaults.\n' >&2
        printf 'A timestamped backup archive of %s/db will be created first.\n' "$PANEL_DIR" >&2
        read -r -p "Type FACTORY to confirm factory reset mode: " confirm
        [[ "$confirm" == "FACTORY" ]] && break
        printf "Factory reset mode not confirmed.\n" >&2
        ;;
      *)
        printf "Enter one of: none, 2fa, factory.\n" >&2
        ;;
    esac
  done
  save_state_checkpoint

  while :; do
    read -r -p "Panel admin username (optional, blank = auto-generate): " input
    PANEL_ADMIN_USER="$input"
    [[ -z "$PANEL_ADMIN_USER" || "$PANEL_ADMIN_USER" =~ ^[A-Za-z0-9_.@-]{3,64}$ ]] && break
    printf 'Panel admin username must match ^[A-Za-z0-9_.@-]{3,64}$.\n' >&2
  done
  save_state_checkpoint

  read -r -s -p "Panel admin password (optional, blank = auto-generate): " PANEL_ADMIN_PASS
  printf '\n'
  save_state_checkpoint

  while :; do
    bool_hint="[y/N]"
    [[ "$ENABLE_PANEL_2FA" == "true" ]] && bool_hint="[Y/n]"
    read -r -p "Enable panel 2FA now? ${bool_hint}: " input
    [[ -n "$input" ]] || input="$ENABLE_PANEL_2FA"
    ENABLE_PANEL_2FA="$(normalize_bool_choice "$input")" || {
      printf "Enter yes/y or no/n.\n" >&2
      continue
    }
    break
  done
  save_state_checkpoint

  while :; do
    bool_hint="[y/N]"
    [[ "$AUTO_CREATE_INBOUND" == "true" ]] && bool_hint="[Y/n]"
    read -r -p "Auto-create VLESS+TLS TCP inbound now? ${bool_hint}: " input
    [[ -n "$input" ]] || input="$AUTO_CREATE_INBOUND"
    AUTO_CREATE_INBOUND="$(normalize_bool_choice "$input")" || {
      printf "Enter yes/y or no/n.\n" >&2
      continue
    }
    break
  done
  save_state_checkpoint

  if [[ "$AUTO_CREATE_INBOUND" == "true" ]]; then
    while :; do
      read -r -p "Auto inbound port [${INBOUND_PORT}] (default 443): " input
      INBOUND_PORT="${input:-$INBOUND_PORT}"
      is_valid_port "$INBOUND_PORT" && break
      printf 'Invalid inbound port. Use 1..65535.\n' >&2
    done
    save_state_checkpoint

    if [[ -n "$INBOUND_REMARK" ]]; then
      read -r -p "Inbound remark [${INBOUND_REMARK}]: " input
      INBOUND_REMARK="${input:-$INBOUND_REMARK}"
    else
      read -r -p "Inbound remark [vless-tls-${DOMAIN}]: " input
      INBOUND_REMARK="${input:-vless-tls-${DOMAIN}}"
    fi
    save_state_checkpoint

    if [[ -n "$INBOUND_CLIENT_EMAIL" ]]; then
      read -r -p "Inbound client email [${INBOUND_CLIENT_EMAIL}]: " input
      INBOUND_CLIENT_EMAIL="${input:-$INBOUND_CLIENT_EMAIL}"
    else
      read -r -p "Inbound client email [client@${DOMAIN}]: " input
      INBOUND_CLIENT_EMAIL="${input:-client@${DOMAIN}}"
    fi
    save_state_checkpoint

    if [[ -n "$INBOUND_SNI" ]]; then
      read -r -p "Inbound TLS SNI/serverName [${INBOUND_SNI}]: " input
      INBOUND_SNI="${input:-$INBOUND_SNI}"
    else
      read -r -p "Inbound TLS SNI/serverName [${DOMAIN}]: " input
      INBOUND_SNI="${input:-${DOMAIN}}"
    fi
    save_state_checkpoint
  fi
fi

OPEN_TCP_PORTS="${OPEN_TCP_PORTS//,/ }"
OPEN_UDP_PORTS="${OPEN_UDP_PORTS//,/ }"
EXPOSE_PANEL_PUBLIC="$(normalize_bool_choice "$EXPOSE_PANEL_PUBLIC" || true)"
ENABLE_PANEL_2FA="$(normalize_bool_choice "$ENABLE_PANEL_2FA" || true)"
AUTO_CREATE_INBOUND="$(normalize_bool_choice "$AUTO_CREATE_INBOUND" || true)"
PANEL_RESET_MODE="$(printf '%s' "$PANEL_RESET_MODE" | tr '[:upper:]' '[:lower:]')"

missing=()
for v in DOMAIN EMAIL OPEN_TCP_PORTS; do
  [[ -n "${!v}" ]] || missing+=("$v")
done
if (( ${#missing[@]} > 0 )); then
  die "Missing required env var(s): ${missing[*]}. Example: DOMAIN=vpn.example.com EMAIL=ops@example.com OPEN_TCP_PORTS='443 8443'"
fi

[[ "$DOMAIN" == *.* ]] || die "DOMAIN must be a valid FQDN."
[[ "$EMAIL" == *"@"* ]] || die "EMAIL must be a valid email address."
is_valid_port "$SSH_PORT" || die "SSH_PORT must be 1..65535."
is_valid_port "$PANEL_PORT" || die "PANEL_PORT must be 1..65535."
is_valid_port "$SUB_PORT" || die "SUB_PORT must be 1..65535."
[[ -n "$PANEL_ADMIN_USER" ]] || PANEL_ADMIN_USER="$(generate_panel_username)"
[[ -n "$PANEL_ADMIN_PASS" ]] || PANEL_ADMIN_PASS="$(generate_strong_secret)"
[[ "$PANEL_ADMIN_USER" =~ ^[A-Za-z0-9_.@-]{3,64}$ ]] || die "PANEL_ADMIN_USER must match ^[A-Za-z0-9_.@-]{3,64}$."
[[ "$PANEL_ADMIN_PASS" != *$'\n'* ]] || die "PANEL_ADMIN_PASS must not contain newline characters."
[[ "$PANEL_CURRENT_PASS" != *$'\n'* ]] || die "PANEL_CURRENT_PASS must not contain newline characters."
[[ -n "$INBOUND_REMARK" ]] || INBOUND_REMARK="vless-tls-${DOMAIN}"
[[ -n "$INBOUND_CLIENT_EMAIL" ]] || INBOUND_CLIENT_EMAIL="client@${DOMAIN}"
[[ -n "$INBOUND_SNI" ]] || INBOUND_SNI="$DOMAIN"
case "$EXPOSE_PANEL_PUBLIC" in
  true|false) ;;
  *) die "EXPOSE_PANEL_PUBLIC must be true or false." ;;
esac
case "$ENABLE_PANEL_2FA" in
  true|false) ;;
  *) die "ENABLE_PANEL_2FA must be true or false." ;;
esac
case "$AUTO_CREATE_INBOUND" in
  true|false) ;;
  *) die "AUTO_CREATE_INBOUND must be true or false." ;;
esac
case "$PANEL_RESET_MODE" in
  none|2fa|factory) ;;
  *) die "PANEL_RESET_MODE must be one of: none, 2fa, factory." ;;
esac
if [[ "$PANEL_RESET_MODE" == "factory" && ! -t 0 && "$PANEL_FACTORY_RESET_CONFIRM" != "FACTORY" ]]; then
  die "PANEL_RESET_MODE=factory requires PANEL_FACTORY_RESET_CONFIRM=FACTORY in non-interactive mode."
fi

if [[ "$AUTO_CREATE_INBOUND" == "true" ]]; then
  is_valid_port "$INBOUND_PORT" || die "INBOUND_PORT must be 1..65535."
  [[ "$INBOUND_CLIENT_EMAIL" == *"@"* ]] || die "INBOUND_CLIENT_EMAIL must be a valid email address."
  [[ -n "$INBOUND_SNI" ]] || die "INBOUND_SNI must not be empty."
  [[ "$INBOUND_PORT" != "$PANEL_PORT" ]] || die "INBOUND_PORT must not be the same as PANEL_PORT."
  [[ "$INBOUND_PORT" != "$SUB_PORT" ]] || die "INBOUND_PORT must not be the same as SUB_PORT."
fi

if [[ -z "${OPEN_TCP_PORTS//[[:space:]]/}" ]]; then
  die "OPEN_TCP_PORTS must contain at least one TCP inbound port (example: '443')."
fi

declare -a TCP_PORTS=()
declare -a UDP_PORTS=()
read -r -a TCP_PORTS <<< "$OPEN_TCP_PORTS"
if [[ -n "${OPEN_UDP_PORTS//[[:space:]]/}" ]]; then
  read -r -a UDP_PORTS <<< "$OPEN_UDP_PORTS"
fi

for p in "${TCP_PORTS[@]}"; do
  is_valid_port "$p" || die "Invalid TCP port in OPEN_TCP_PORTS: $p"
done
for p in "${UDP_PORTS[@]}"; do
  is_valid_port "$p" || die "Invalid UDP port in OPEN_UDP_PORTS: $p"
done

if [[ "$AUTO_CREATE_INBOUND" == "true" ]] && ! array_contains "$INBOUND_PORT" "${TCP_PORTS[@]}"; then
  TCP_PORTS+=("$INBOUND_PORT")
  log "Added inbound auto-create port ${INBOUND_PORT}/tcp to firewall allow list."
fi

export DEBIAN_FRONTEND=noninteractive
log "Installing base packages"
apt-get update -y
apt-get install -y --no-install-recommends \
  adduser ca-certificates certbot curl fail2ban gnupg lsb-release openssl python3 sudo ufw
mark_step_applied "packages"

NAME_REGEX="$(read_name_regex)"
regex_rc=0
printf 'testuser\n' | grep -Eq -- "$NAME_REGEX" 2>/dev/null || regex_rc=$?
if [[ "$regex_rc" -eq 2 ]]; then
  NAME_REGEX='^[a-z][-a-z0-9_]*$'
fi
SAFE_USER_REGEX='^[a-z][-a-z0-9_]{0,31}$'

username_is_valid() {
  local name="$1"
  [[ "$name" =~ $SAFE_USER_REGEX ]] || return 1
  printf '%s\n' "$name" | grep -Eq -- "$NAME_REGEX"
}

generate_username() {
  local candidate=""
  local i
  for (( i = 0; i < 50; i++ )); do
    candidate="u$(tr -dc 'a-z0-9' </dev/urandom | head -c 14)"
    if username_is_valid "$candidate" && ! id -u "$candidate" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

if [[ -z "$NEW_USER" ]]; then
  NEW_USER="$(generate_username)" || die "Failed to auto-generate a valid username for NAME_REGEX=${NAME_REGEX}."
fi
username_is_valid "$NEW_USER" || die "NEW_USER '$NEW_USER' failed validation (safe policy + NAME_REGEX=${NAME_REGEX})."

USER_PREEXISTED=false
if id -u "$NEW_USER" >/dev/null 2>&1; then
  USER_PREEXISTED=true
fi

if [[ "$USER_PREEXISTED" == "false" ]]; then
  log "Creating user $NEW_USER"
  adduser --disabled-password --gecos "" "$NEW_USER"
else
  log "User $NEW_USER already exists (keeping existing account)"
fi

SSH_PASSWORD_CHANGED="false"
SSH_PASSWORD_DISPLAY="unchanged (existing user password retained)"
SSH_PASSWORD_CRED_VALUE="UNCHANGED_EXISTING_USER"
if [[ -n "$NEW_PASS" ]]; then
  [[ "$NEW_PASS" != *$'\n'* ]] || die "NEW_PASS must not contain newline characters."
  NEW_PASS_HASH="$(printf '%s' "$NEW_PASS" | openssl passwd -6 -stdin)"
  usermod --password "$NEW_PASS_HASH" "$NEW_USER"
  SSH_PASSWORD_CHANGED="true"
  SSH_PASSWORD_DISPLAY="$NEW_PASS"
  SSH_PASSWORD_CRED_VALUE="$NEW_PASS"
elif [[ "$USER_PREEXISTED" == "false" ]]; then
  NEW_PASS="$(openssl rand -base64 30 | tr -d '\n' | cut -c1-24)"
  NEW_PASS_HASH="$(printf '%s' "$NEW_PASS" | openssl passwd -6 -stdin)"
  usermod --password "$NEW_PASS_HASH" "$NEW_USER"
  SSH_PASSWORD_CHANGED="true"
  SSH_PASSWORD_DISPLAY="$NEW_PASS"
  SSH_PASSWORD_CRED_VALUE="$NEW_PASS"
elif ! user_has_usable_password "$NEW_USER"; then
  NEW_PASS="$(openssl rand -base64 30 | tr -d '\n' | cut -c1-24)"
  NEW_PASS_HASH="$(printf '%s' "$NEW_PASS" | openssl passwd -6 -stdin)"
  usermod --password "$NEW_PASS_HASH" "$NEW_USER"
  SSH_PASSWORD_CHANGED="true"
  SSH_PASSWORD_DISPLAY="$NEW_PASS"
  SSH_PASSWORD_CRED_VALUE="$NEW_PASS"
  log "Existing user ${NEW_USER} had no usable password; generated and applied a new strong password."
else
  log "Keeping existing SSH password for pre-existing user ${NEW_USER} (no new password provided)."
fi

usermod -aG sudo "$NEW_USER"
ensure_passwordless_sudo "$NEW_USER"
if [[ "$USER_PREEXISTED" == "true" && "$USER_EXPLICIT" == "true" ]]; then
  log "Verified existing explicit user ${NEW_USER} has sudo group membership and passwordless sudo."
fi
mark_step_applied "user+sudo"

if [[ -z "$SSH_ALLOW_USERS" ]]; then
  SSH_ALLOW_USERS="$NEW_USER"
fi

log "Applying SSH hardening"
ensure_sshd_dropin_include
rm -f /etc/ssh/sshd_config.d/99-3xui-hardening.conf
cat > /etc/ssh/sshd_config.d/00-3xui-hardening.conf <<EOF
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
KbdInteractiveAuthentication no
AllowUsers ${SSH_ALLOW_USERS}
EOF

/usr/sbin/sshd -t
validate_sshd_root_login_no "before restart"
ROOT_SSH_DISABLED_CONFIRMED="pending (restart deferred until after ufw enable)"
mark_step_applied "ssh hardening"

log "Configuring fail2ban for SSH"
cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
backend = systemd
port = ${SSH_PORT}
maxretry = 5
findtime = 10m
bantime = 1h
banaction = ufw
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban
mark_step_applied "fail2ban"

log "Installing Docker"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker
mark_step_applied "docker"
if ! docker compose version >/dev/null 2>&1; then
  apt-get install -y docker-compose-plugin
fi
mark_step_applied "compose"
if getent group docker >/dev/null 2>&1; then
  usermod -aG docker "$NEW_USER"
fi

log "Preparing 3x-ui files"
install -d -m 700 "${PANEL_DIR}/db" "${PANEL_DIR}/cert"
cat > "${PANEL_DIR}/docker-compose.yml" <<EOF
services:
  3x-ui:
    image: ${IMAGE}
    container_name: ${CONTAINER_NAME}
    volumes:
      - ./db/:/etc/x-ui/
      - ./cert/:/root/cert/
    environment:
      XRAY_VMESS_AEAD_FORCED: "false"
      XUI_ENABLE_FAIL2BAN: "true"
    tty: true
    network_mode: host
    restart: unless-stopped
EOF

log "Starting 3x-ui container"
(
  cd "$PANEL_DIR"
  docker compose pull
  docker compose up -d
)

log "Waiting for 3x-ui panel/API readiness"
PANEL_COOKIE_FILE="$(mktemp /tmp/3xui-panel-cookie.XXXXXX)"
panel_wait_ready || die "3x-ui panel did not become reachable on port ${PANEL_PORT}."
panel_detect_access || die "Could not detect 3x-ui panel base path or HTTP scheme."
log "Detected panel endpoint ${PANEL_API_ORIGIN}${PANEL_BASE_PATH}"

log "Applying panel admin credentials"
panel_apply_credentials

log "Configuring UFW"
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp"
ufw allow 80/tcp
ufw allow 443/tcp
for p in "${TCP_PORTS[@]}"; do
  ufw allow "${p}/tcp"
done
for p in "${UDP_PORTS[@]}"; do
  ufw allow "${p}/udp"
done

if [[ "$EXPOSE_PANEL_PUBLIC" == "false" ]]; then
  if ! array_contains "$PANEL_PORT" "${TCP_PORTS[@]}"; then
    ufw deny "${PANEL_PORT}/tcp" || true
  fi
  if ! array_contains "$SUB_PORT" "${TCP_PORTS[@]}"; then
    ufw deny "${SUB_PORT}/tcp" || true
  fi
fi
ufw --force enable
mark_step_applied "ufw"
log "Applying pending SSH daemon restart after UFW enable"
if systemctl list-unit-files | grep -q '^ssh\.service'; then
  systemctl restart ssh
else
  systemctl restart sshd
fi
validate_sshd_root_login_no "after restart"
ROOT_SSH_DISABLED_CONFIRMED="yes"
mark_step_applied "ssh restart"

log "Issuing/refreshing Let's Encrypt certificate for ${DOMAIN}"
certbot certonly \
  --standalone \
  --non-interactive \
  --agree-tos \
  --email "$EMAIL" \
  --keep-until-expiring \
  -d "$DOMAIN"

log "Installing cert deploy hook"
cat > /usr/local/sbin/3xui-cert-deploy.sh <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
SRC_DIR="/etc/letsencrypt/live/${DOMAIN}"
DST_DIR="${PANEL_DIR}/cert/live/${DOMAIN}"
install -d -m 700 "\$DST_DIR"
install -m 600 "\$SRC_DIR/fullchain.pem" "\$DST_DIR/fullchain.pem"
install -m 600 "\$SRC_DIR/privkey.pem" "\$DST_DIR/privkey.pem"
docker restart "${CONTAINER_NAME}" >/dev/null 2>&1 || true
EOF
chmod 700 /usr/local/sbin/3xui-cert-deploy.sh
/usr/local/sbin/3xui-cert-deploy.sh
mark_step_applied "cert deploy"

if [[ "$AUTO_CREATE_INBOUND" == "true" || "$ENABLE_PANEL_2FA" == "true" ]]; then
  log "Finalizing panel API configuration"
  panel_wait_ready || die "3x-ui panel did not recover after certificate deployment."
  panel_login "$PANEL_ADMIN_USER" "$PANEL_ADMIN_PASS" "$PANEL_CURRENT_2FA_CODE" || die "Panel login failed before API finalization."

  if [[ "$AUTO_CREATE_INBOUND" == "true" ]]; then
    log "Ensuring requested VLESS+TLS inbound exists"
    panel_ensure_vless_inbound
  fi

  if [[ "$ENABLE_PANEL_2FA" == "true" ]]; then
    log "Ensuring panel 2FA is enabled"
    panel_enable_two_factor
  fi
  mark_step_applied "final api actions"
fi

cat > /etc/systemd/system/3xui-cert-renew.service <<'EOF'
[Unit]
Description=Renew Let's Encrypt certificates for 3x-ui and deploy to /opt/3x-ui/cert
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet --deploy-hook /usr/local/sbin/3xui-cert-deploy.sh
EOF

cat > /etc/systemd/system/3xui-cert-renew.timer <<'EOF'
[Unit]
Description=Twice-daily certificate renewal for 3x-ui

[Timer]
OnCalendar=*-*-* 03,15:00:00
RandomizedDelaySec=45m
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now 3xui-cert-renew.timer
mark_step_applied "renew timer"

CRED_FILE="/root/3x-ui-bootstrap-credentials.txt"
cat > "$CRED_FILE" <<EOF
SSH_USER=${NEW_USER}
SSH_PASSWORD=${SSH_PASSWORD_CRED_VALUE}
SSH_PASSWORD_CHANGED=${SSH_PASSWORD_CHANGED}
PANEL_ADMIN_USER=${PANEL_ADMIN_USER}
PANEL_ADMIN_PASSWORD=${PANEL_ADMIN_PASS}
PANEL_BASE_PATH=${PANEL_BASE_PATH}
PANEL_LOCAL_URL=${PANEL_API_ORIGIN}${PANEL_BASE_PATH}
PANEL_CREDS_APPLY_METHOD=${PANEL_CREDS_METHOD}
PANEL_API_LOGIN_AVAILABLE=${PANEL_API_LOGIN_AVAILABLE}
PANEL_RESET_MODE=${PANEL_RESET_MODE}
PANEL_RESET_ACTION=${PANEL_RESET_ACTION}
PANEL_RESET_RESULT=${PANEL_RESET_RESULT}
PANEL_FACTORY_BACKUP_PATH=${PANEL_FACTORY_BACKUP_PATH}
PANEL_2FA_RESET_FOR_API=${PANEL_2FA_RESET_FOR_API}
PANEL_2FA_ENABLED=${PANEL_2FA_EFFECTIVE}
PANEL_2FA_TOKEN=${PANEL_2FA_TOKEN}
AUTO_INBOUND_STATUS=${INBOUND_STATUS}
AUTO_INBOUND_PORT=${INBOUND_PORT}
AUTO_INBOUND_ID=${INBOUND_ID}
AUTO_INBOUND_CLIENT_ID=${INBOUND_CLIENT_ID}
AUTO_INBOUND_CLIENT_EMAIL=${INBOUND_CLIENT_EMAIL}
DOMAIN=${DOMAIN}
PANEL_DIR=${PANEL_DIR}
ROOT_SSH_DISABLED_CONFIRMED=${ROOT_SSH_DISABLED_CONFIRMED}
EOF
chmod 600 "$CRED_FILE"

log "Running post-install checks"
systemctl is-active --quiet docker || die "docker is not active"
systemctl is-active --quiet fail2ban || die "fail2ban is not active"
systemctl is-active --quiet 3xui-cert-renew.timer || die "3xui-cert-renew.timer is not active"
docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME" || die "container ${CONTAINER_NAME} is not running"
[[ -s "${PANEL_DIR}/cert/live/${DOMAIN}/fullchain.pem" ]] || die "fullchain.pem not found"
[[ -s "${PANEL_DIR}/cert/live/${DOMAIN}/privkey.pem" ]] || die "privkey.pem not found"

PUBLIC_IP="$(curl -4fsS https://api.ipify.org || true)"
PANEL_PUBLIC_URL="https://${DOMAIN}:${PANEL_PORT}${PANEL_BASE_PATH}"
SUB_PUBLIC_URL="https://${DOMAIN}:${SUB_PORT}/"
TUNNEL_PANEL_URL="http://127.0.0.1:8080${PANEL_BASE_PATH}"
LOCAL_PANEL_URL="${PANEL_API_ORIGIN}${PANEL_BASE_PATH}"

if [[ "$PANEL_2FA_EFFECTIVE" == "true" ]]; then
  TWO_FACTOR_SUMMARY="enabled"
else
  TWO_FACTOR_SUMMARY="disabled"
fi

if [[ "$INBOUND_STATUS" == "not-requested" ]]; then
  INBOUND_DETAILS="Inbound auto-creation: not requested"
else
  INBOUND_DETAILS="$(cat <<EOF
Inbound auto-creation: ${INBOUND_STATUS}
Inbound protocol: VLESS TCP TLS
Inbound port: ${INBOUND_PORT}
Inbound SNI: ${INBOUND_SNI}
Inbound id: ${INBOUND_ID:-n/a}
Inbound client email: ${INBOUND_CLIENT_EMAIL}
Inbound client UUID: ${INBOUND_CLIENT_ID:-n/a}
EOF
)"
fi

cat <<EOF

Install finished.

Credentials saved: ${CRED_FILE}
SSH login: ${NEW_USER}
SSH password: ${SSH_PASSWORD_DISPLAY}
Panel admin username: ${PANEL_ADMIN_USER}
Panel admin password: ${PANEL_ADMIN_PASS}
Panel base path: ${PANEL_BASE_PATH}
Panel credential apply method: ${PANEL_CREDS_METHOD}
Panel API login available: ${PANEL_API_LOGIN_AVAILABLE}
Panel recovery mode: ${PANEL_RESET_MODE}
Panel recovery action: ${PANEL_RESET_ACTION}
Panel recovery result: ${PANEL_RESET_RESULT}
Panel factory backup: ${PANEL_FACTORY_BACKUP_PATH:-not-created}
Panel 2FA reset by CLI for API access: ${PANEL_2FA_RESET_FOR_API}
Panel 2FA: ${TWO_FACTOR_SUMMARY}
Panel 2FA token (save in authenticator): ${PANEL_2FA_TOKEN:-not-enabled}
Panel exposure: ${EXPOSE_PANEL_PUBLIC}
Root SSH login disabled: confirmed (PermitRootLogin no)

${INBOUND_DETAILS}

Links:
  Local panel URL on server: ${LOCAL_PANEL_URL}
  Local tunnel panel URL: ${TUNNEL_PANEL_URL}
  Public panel URL: ${PANEL_PUBLIC_URL}
  Public subscription URL: ${SUB_PUBLIC_URL}

Setup instructions:
  1) Connect with SSH:
     ssh -p ${SSH_PORT} ${NEW_USER}@${PUBLIC_IP:-<SERVER_IP>}
  2) If panel is private, create tunnel:
     ssh -p ${SSH_PORT} -L 8080:127.0.0.1:${PANEL_PORT} ${NEW_USER}@${PUBLIC_IP:-<SERVER_IP>}
  3) Open the panel:
     ${TUNNEL_PANEL_URL} (private mode) or ${PANEL_PUBLIC_URL} (public mode)
  4) Log in to 3x-ui with:
     username: ${PANEL_ADMIN_USER}
     password: ${PANEL_ADMIN_PASS}
  5) If 2FA is enabled, add token ${PANEL_2FA_TOKEN:-N/A} to your authenticator and enter the generated code at login.

Certificate inside container:
  /root/cert/live/${DOMAIN}/fullchain.pem
  /root/cert/live/${DOMAIN}/privkey.pem

Post-install verification commands:
  docker compose -f ${PANEL_DIR}/docker-compose.yml ps
  sudo ufw status numbered
  sudo fail2ban-client status sshd
  sudo systemctl status 3xui-cert-renew.timer --no-pager
  sudo ls -l ${PANEL_DIR}/cert/live/${DOMAIN}

EOF
