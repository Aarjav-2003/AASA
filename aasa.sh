#!/bin/bash
# Android Application Static Analyzer (AASA)
# Usage:
#   ./aasa.sh -f app.apk
#   ./aasa.sh -u https://example.com/app.apk

set -euo pipefail

OUTDIR="output"
HASHLIST="malicious_hashes.txt"
PYTHON="python3"
ANALYZER="cli.py"

mkdir -p "$OUTDIR"

usage() {
  echo "Usage: $0 -f <apk_file> | -u <apk_url>"
  exit 1
}

# --- Argument parsing ---
APKFILE=""
while getopts "f:u:" opt; do
  case $opt in
    f) APKFILE="$OPTARG" ;;
    u) 
      APKFILE="$OUTDIR/downloaded.apk"
      echo "[*] Downloading from $OPTARG ..."
      curl -L -o "$APKFILE" "$OPTARG"
      ;;
    *) usage ;;
  esac
done

if [[ -z "$APKFILE" ]]; then
  usage
fi

# --- Check if file exists ---
if [[ ! -f "$APKFILE" ]]; then
  echo "[!] APK file not found: $APKFILE"
  exit 3
fi

# --- Compute hash ---
HASH=$(sha256sum "$APKFILE" | awk '{print $1}')
echo "[*] SHA256: $HASH"

# --- Quick hash check ---
if [[ -f "$HASHLIST" ]] && grep -q "$HASH" "$HASHLIST"; then
  echo "[!] Match found in malicious hash list!"
  exit 2
fi

# --- Run analyzer ---
echo "[*] Running static analysis..."
$PYTHON "$ANALYZER" -f "$APKFILE" -o "$OUTDIR"

RESULT=$?
if [[ $RESULT -eq 2 ]]; then
  echo "[!] ALERT: Suspicious characteristics detected."
elif [[ $RESULT -eq 0 ]]; then
  echo "[+] SAFE: No major red flags."
else
  echo "[!] ERROR: Analyzer failed."
fi

exit $RESULT
