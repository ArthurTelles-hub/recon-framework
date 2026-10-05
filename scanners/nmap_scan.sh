#!/bin/bash
# scanners/nmap_scan.sh - runs the nmap scan against the target
#
# Usage: nmap_scan.sh <target> <output_dir> <fast_mode(0|1)>

set -euo pipefail

TARGET="$1"
OUTDIR="$2"
FAST_MODE="${3:-0}"

mkdir -p "$OUTDIR"

if [[ "$FAST_MODE" == "1" ]]; then
    # Fast scan: top 100 ports, no full version-detection sweep
    NMAP_ARGS=(-sV -T4 --top-ports 100)
else
    # Full scan: all TCP ports + service/version detection + default script
    NMAP_ARGS=(-sV -sC -T4 -p-)
fi

echo "[nmap] Running: nmap ${NMAP_ARGS[*]} -oA ${OUTDIR}/scan ${TARGET}"

nmap "${NMAP_ARGS[@]}" \
    -oA "${OUTDIR}/scan" \
    "${TARGET}"

echo "[nmap] Done. Results in ${OUTDIR}/ (scan.xml, scan.nmap, scan.gnmap)"