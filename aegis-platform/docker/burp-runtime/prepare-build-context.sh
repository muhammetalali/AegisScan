#!/bin/sh
set -eu
test "$#" -eq 2 || { echo 'Usage: prepare-build-context.sh VERIFIED_RUNTIME NEW_PRIVATE_CONTEXT' >&2; exit 2; }
runtime=$1
context=$2
test ! -e "$context"
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
umask 077
mkdir -p "$context/vendor"
cp "$source_dir/Dockerfile" "$source_dir/entrypoint.sh" "$context/"
cp "$runtime/burpsuite-desktop-2026.9.jar" "$runtime/burp-mcp-all.jar" "$context/vendor/"
(cd "$context/vendor" && \
  echo 'd6c80be60575b59a3097e939b1cf4acf2efd104c0f6ed05166753180365fc7fc  burpsuite-desktop-2026.9.jar' | sha256sum -c - && \
  echo 'f93e434a9154fbb03bc9b20e46555fc901be57a80ec63d607d9cde192d27691c  burp-mcp-all.jar' | sha256sum -c -)
