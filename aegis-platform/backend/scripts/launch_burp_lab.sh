#!/bin/bash
set -euo pipefail
runtime="${AEGIS_BURP_LAB_RUNTIME:-/home/aegisadmin/aegis-burp-lab-runtime}"
jar="$runtime/burpsuite-desktop-2026.9.jar"
java="$runtime/java/bin/java"
expected=d6c80be60575b59a3097e939b1cf4acf2efd104c0f6ed05166753180365fc7fc
test -x "$java"
test -f "$jar"
actual=$(sha256sum "$jar")
test "${actual%% *}" = "$expected"
mkdir -p "$runtime/profile" "$runtime/profile/prefs"
exec "$java" -Xmx1024m -Duser.home="$runtime/profile" \
  -Djava.util.prefs.userRoot="$runtime/profile/prefs" -jar "$jar" \
  --data-dir="$runtime/profile/data" --disable-auto-update
