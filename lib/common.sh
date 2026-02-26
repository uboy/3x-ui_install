#!/usr/bin/env bash

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() { printf "[%s] ${BLUE}INFO${NC}  %s
" "$(date '+%F %T')" "$*"; }
warn() { printf "[%s] ${YELLOW}WARN${NC}  %s
" "$(date '+%F %T')" "$*"; }
error() { printf "[%s] ${RED}ERROR${NC} %s
" "$(date '+%F %T')" "$*"; }
success() { printf "[%s] ${GREEN}OK${NC}    %s
" "$(date '+%F %T')" "$*"; }

die() {
  local message="$*"
  [[ -n "$message" ]] || message="Unknown error."
  error "$message"
  exit 1
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
