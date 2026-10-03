#!/bin/sh
set -eu
test -n "${DISPLAY:-}"
test -r "${XAUTHORITY:-/nonexistent}"
test -d /var/lib/aegis-burp/profile
test -w /var/lib/aegis-burp/profile
exec /opt/java/openjdk/bin/java -Xmx1024m \
  -Duser.home=/var/lib/aegis-burp/profile \
  -Djava.util.prefs.userRoot=/var/lib/aegis-burp/profile/prefs \
  -jar /opt/burp/burpsuite-desktop-2026.9.jar \
  --data-dir=/var/lib/aegis-burp/profile/data --disable-auto-update
