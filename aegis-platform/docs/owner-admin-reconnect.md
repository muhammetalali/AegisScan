# Owner lab maintenance: resilient SSH session (initial integration)

This helper provides an **interactive, operator-initiated** administration connection
to a company-managed host. It is not a reverse shell, an implant, or a browser
remote-execution API. Its role is to recover from temporary connectivity loss
without discarding the interactive session on the managed host.

## Requirements

- A managed Linux lab machine running OpenSSH server and `tmux`.
- An administrative SSH account on that host, with the privileges assigned by
  the host operator. The helper does **not** grant or modify `sudo` privileges.
- Network reachability from the owner's workstation to the lab host, directly
  or through an approved management VPN/overlay.
- OpenSSH client and Bash on the owner's workstation.
- An existing SSH host alias and a verified, pinned SSH server host key. For example,
  the *operator's* `~/.ssh/config` can contain:

  ```sshconfig
  Host managed-lab-01
    HostName <the-managed-host-address>
    User <existing-admin-user>
    IdentityFile ~/.ssh/<existing-approved-identity>
    IdentitiesOnly yes
    StrictHostKeyChecking yes
  ```

  Install the host's verified public key in `~/.ssh/known_hosts` through
  your normal device enrollment procedure. Do not disable host key checks.

## Connect and recover

From the owner's machine:

```bash
bash aegis-platform/scripts/owner_admin_reconnect.sh managed-lab-01
```

The script connects using the preconfigured SSH identity and attaches to the
`aegis-owner-maintenance` tmux session (or creates it on first access).
If the SSH transport drops, it retries using capped exponential backoff
(2, 4, 8, 16, 32, 64 seconds). It does not create any extra privileged agent
on the remote host. Commands are entered **interactively** after SSH login.

The remote tmux session can survive disconnections, provided the host stays
running and the tmux server is not stopped. Detach using `Ctrl+B`, then `D`;
launch the helper again to resume. Close the tmux session normally to finish.

## Boundaries and operational facts

- When the owner's laptop is off or the network is down, there is no live SSH
  connection; the remote tmux session can still retain its state.
- Remote SSH and `sudo` permissions are enforced by the target operating system.
  If an account loses authorization, reconnecting cannot restore it.
- Server keys, SSH identities, and any access to a management VPN must be
  provisioned securely through existing administration.
- This helper does not automatically log command output to the AegisScan
  evidence ledger. Remote administration audit integration is separate work.
- This first deliverable does **not** add an interactive terminal to the
  AegisScan browser or configure unattended reverse connections.
