#!/bin/bash

APK_DIR=$1
OUTPUT_DIR="output"
THRESHOLD=50

if [ -z "$APK_DIR" ]; then
    echo "Usage: $0 <apk_directory>"
    exit 1
fi

mkdir -p $OUTPUT_DIR

for apk in "$APK_DIR"/*.apk; do
    if [ ! -f "$apk" ]; then
        echo "No APK files found in $APK_DIR"
        continue
    fi

    echo "Analyzing $apk ..."

    base_name=$(basename "$apk" .apk)
    report_file="$OUTPUT_DIR/${base_name}_report.txt"
    json_file="$OUTPUT_DIR/${base_name}_report.json"

    python cli.py -f "$apk" -o "$report_file" -j "$json_file"

    risk_score=$(grep "Risk Score:" "$report_file" | awk '{print $3}')

    if [ -n "$risk_score" ] && [ "$risk_score" -ge "$THRESHOLD" ]; then
        echo -e "\033[91m⚠️ ALERT: $apk has high risk score ($risk_score)\033[0m"
    elif [ -n "$risk_score" ]; then
        echo -e "\033[92m✅ $apk is low/medium risk ($risk_score)\033[0m"
    fi
done
