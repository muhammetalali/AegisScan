#!/usr/bin/env bash
# Prepare ONLY the disposable filesystem of a GitHub-hosted Ubuntu Actions runner.
# Never run this cleanup on production Ubuntu, a self-hosted runner, or an operator laptop.
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted || "${RUNNER_OS:-}" != Linux ]]; then
  echo "Refusing disk cleanup outside an ephemeral GitHub-hosted Linux runner" >&2
  exit 2
fi

before_kib="$(df -Pk / | awk 'NR==2 {print $4}')"
echo "GITHUB_RUNNER_DISK_BEFORE_KIB=${before_kib}"
df -h /

# These are preinstalled SDKs that AegisScan's Docker-based CI jobs do not use.
# Deliberately leave Docker images, CI evidence, checkout, Python, Git, and caches intact.
for unused_path in \
  /usr/local/lib/android \
  /usr/share/dotnet \
  /usr/local/share/powershell \
  /opt/hostedtoolcache/CodeQL \
  /opt/ghc; do
  if [[ -d "${unused_path}" && ! -L "${unused_path}" ]]; then
    echo "Reclaim unused GitHub-hosted SDK: ${unused_path}"
    sudo rm -rf -- "${unused_path}"
  fi
done

after_kib="$(df -Pk / | awk 'NR==2 {print $4}')"
echo "GITHUB_RUNNER_DISK_AFTER_KIB=${after_kib}"
df -h /

# Building the exact legacy scanner and multi-stage recon runtime in one
# job requires an explicit capacity check, rather than failing halfway through
# apt/dpkg and misdiagnosing an application defect.
minimum_kib=15728640  # 15 GiB
if (( after_kib < minimum_kib )); then
  echo "Insufficient ephemeral runner capacity for exact-head Docker validation: ${after_kib} KiB < ${minimum_kib} KiB" >&2
  exit 1
fi
echo "GITHUB_RUNNER_DISK_GATE=PASS"
