#!/usr/bin/env bash
# Reconnect to a company-managed SSH host and reattach the same tmux maintenance session.
# Run interactively from the owner's workstation. Host aliases must already be
# provisioned in ~/.ssh/config with a trusted host key and an approved login key.
set -uo pipefail

usage() {
  printf 'Usage: %s <configured-ssh-host-alias>\n' "$0" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage
alias_name="$1"
[[ "$alias_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || usage
command -v ssh >/dev/null || { echo 'OpenSSH client is required.' >&2; exit 127; }

# The remote user receives only the permissions already assigned by that
# host's SSH/sudo policies; this script does not install an agent or grant root.
remote_command='exec tmux new-session -A -s aegis-owner-maintenance'
attempt=0
trap 'echo "Connection closed by operator." >&2; exit 130' INT
trap 'exit 143' TERM

while :; do
  ssh -tt -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o ServerAliveInterval=20 -o ServerAliveCountMax=3 \
    -o ConnectTimeout=10 -o ConnectionAttempts=1 \
    -- "$alias_name" "$remote_command"
  code=$?
  if [[ $code -eq 0 ]]; then
    exit 0  # Exiting tmux intentionally ends automatic reconnection.
  fi
  if [[ $code -ne 255 ]]; then
    printf 'Remote session exited with status %d; not retrying.\n' "$code" >&2
    exit "$code"
  fi
  attempt=$(( attempt < 6 ? attempt + 1 : 6 ))
  delay=$(( 2 ** attempt ))
  printf 'SSH connection lost; retrying in %ss. Press Ctrl+C to stop.\n' "$delay" >&2
  sleep "$delay" || exit 130
done
