#!/usr/bin/env sh
set -eu

rm -rf .zig-cache zig-out
rm -f audit-scan.json audit.log report.html

echo "Clean completed."
