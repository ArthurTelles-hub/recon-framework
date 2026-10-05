#!/bin/bash
#
# recon.sh - main orchestrator for the reconnaissance framework
# Usage:
#   ./recon.sh -t <alvo> [-o <diretorio_saida>] [--fast]
#
#  WARNING: only use this against targets you are explicity authorized
# to test (you own labs, HTB, TryHackMe, CTFs, or your own infrastruture).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/utils.sh"

TARGET=""
OUTDIR=""
FAST_MODE=0

usage() {
    cat <<EOF
Usage: $0 -t <target> [-o <output_dir>] [--fast]

    -t <target>    Target IP or domain (required)
    -o <dir>       Output directory (default: targets/<target>)
    --fast         Faster scan (fewer ports / less depth)
    -h             Show this help message
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in 
        -t) 
            TARGET="$2"
            shift 2    
            ;;
        -o) 
            OUTDIR="$2" 
            shift 2 
            ;;
        --fast) 
            FAST_MODE=1 
            shift 
            ;;
        -h|--help) 
            usage 
            ;;
        *) 
            log_error "Unknown argument: $1"
            usage 
            ;;
    esac
done

[[ -z "$TARGET" ]] && { log_error "No target provided (-t)."; usage; }
[[ -z "$OUTDIR" ]] && OUTDIR="${SCRIPT_DIR}/targets/${TARGET}"

check_dependencies nmap python3

mkdir -p "$OUTDIR"/{nmap,web,enum,reports}
log_info "Target: ${TARGET}"
log_info "Output: ${OUTDIR}"

# --- step 1: port/service scan ---
log_info "Starting nmap scan..."
"${SCRIPT_DIR}/scanners/nmap_scan.sh" "$TARGET" "$OUTDIR/nmap" "$FAST_MODE"

NMAP_XML="${OUTDIR}/nmap/scan.xml"

# --- step 2: parse results and generate suggestions --- 
if [[ -f "$NMAP_XML" ]]; then
    log_info "Analyzing nmap results..."
    python3 "${SCRIPT_DIR}/parser/parse_nmap.py" "$NMAP_XML" \
    --out "${OUTDIR}/enum/suggestions.json" \
    --target "$TARGET"
else
    log_warn "nmap XML file not found, skipping analysis."
fi

# --- step 2.5: (optional) AI_based enrichment ---
# Only runs if AI_API_KEY is set. A failure here never breaks the pipeline -
# the static suggestions.json from step 2 is always preserved.
#
#if [[ -n "${AI_API_KEY:-}" ]] && [[ -f "${OUTDIR}/enum/suggestions.json" ]]; then
#    log_info "Enriching suggestions with AI..."
#    if python3 "${SCRIPT_DIR}/ai/analyze.py" "${OUTDIR}/enum/suggestions.json" \
#        --out "${OUTDIR}/enum/suggestions_ai.json"; then
#        log_info "AI-enriched suggestions: ${OUTDIR}/enum/suggestions_ai.json"
#   else
#       log_warn "AI enrichment failed, continuing with static suggestions only."
#   fi
#else
#    log_info "AI_API_KEY not set, skipping AI enrichment (static suggestions only)."
#fi
#

log_info "Initial reconnaissance complete."
log_info "Suggested next steps in: ${OUTDIR}/enum/suggestions.json"

# --- step 3: consolidated report ---
log_info "Generating report..."
REPORT_FILE="${OUTDIR}/reports/report.md"
if python3 "${SCRIPT_DIR}/report/generate_report.py" "$OUTDIR" \
    --out "$REPORT_FILE"; then
    log_info "Report saved to: ${REPORT_FILE}"
    echo ""
    echo "=================================================="
    echo " SUGGESTIONS SUMARY "
    echo "=================================================="
    cat "$REPORT_FILE"
    echo "=================================================="
else
    log_warn "Report generation failed."
fi