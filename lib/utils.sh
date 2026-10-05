#!/bin/bash
# lib/utils.sh - shared functions (logging, dependency checks)

# Colors (autoatically disable if output is not a terminal)
if [[ -t 1 ]]; then
    C_RESET='\033[0m'
    C_INFO='\033[0;36m'
    C_WARN='\033[0;33m'
    C_ERROR='\033[0;31m'
else
    C_RESET='' C_INFO='' C_WARN='' C_ERROR=''
fi

_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log_info() {
    echo -e "${C_INFO}[INFO $(_timestamp)]${C_RESET} $*"
}

log_warn() {
    echo -e "${C_WARN}[WARN $(_timestamp)]${C_RESET} $*" >&2
}

log_error() {
    echo -e "${C_ERROR}[ERROR $(_timestamp)]${C_RESET} $*" >&2
}

# check_dependencies cmd1 cmd2 ...
# Checks whether required binaries are installed; aborts if any missing.
check_dependencies() {
    local missing=()
    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then 
            missing+=("$cmd")
        fi
    done
    if (( ${#missing[@]} > 0 )); then
        log_error "Missing dependencies: ${missing[*]}"
        log_error "Install them before continuing."
        exit 1
    fi
}