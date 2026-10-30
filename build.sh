#!/usr/bin/env bash
# ============================================================
#  Chingtsi WAF - build script (Linux / macOS, JDK 17+ only)
#  Produces dist/chingtsi-waf.jar, version taken from the VERSION file.
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

VERSION="$(tr -d "\r\n" < VERSION)"
[ -n "$VERSION" ] || VERSION="1.0.0.0"
OUT="build/classes"
mkdir -p "$OUT" dist

if ! command -v javac >/dev/null 2>&1; then
  echo "[ERR] javac not found. Install JDK 17 or newer and put it on PATH." >&2
  exit 1
fi

echo "[1/3] Compiling sources..."
find src -name '*.java' > build/sources.txt
javac -encoding UTF-8 -d "$OUT" @build/sources.txt

echo "[2/3] Copying resources..."
mkdir -p "$OUT/com/chingtsi/waf/ui"
cp src/com/chingtsi/waf/ui/*.png "$OUT/com/chingtsi/waf/ui/"

echo "[3/3] Packaging chingtsi-waf.jar..."
cat > build/manifest.mf <<EOF
Manifest-Version: 1.0
Main-Class: com.chingtsi.waf.WafMain
Implementation-Title: Chingtsi WAF
Implementation-Version: ${VERSION}
Implementation-Vendor: Chingtsi Studio
EOF
jar --create --file dist/chingtsi-waf.jar --manifest build/manifest.mf -C "$OUT" .

echo
echo "Build OK -> $(pwd)/dist/chingtsi-waf.jar   (version ${VERSION})"
echo "Console   : java -cp \"dist/chingtsi-waf.jar:lib/flatlaf.jar\" com.chingtsi.waf.ui.DashboardMain"
