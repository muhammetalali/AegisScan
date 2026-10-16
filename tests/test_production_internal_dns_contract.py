from pathlib import Path
import subprocess
import sys

import yaml

ROOT = Path(__file__).parents[1]


def test_systemd_ddns_contract_is_hardened_periodic_and_environment_bound():
    service = (ROOT / "aegis-platform/systemd/aegisscan-ddns-reconcile.service").read_text()
    timer = (ROOT / "aegis-platform/systemd/aegisscan-ddns-reconcile.timer").read_text()
    assert "NoNewPrivileges=yes" in service
    assert "ProtectSystem=strict" in service
    assert "IPAddressDeny=any" in service
    assert "IPAddressAllow=192.168.49.53/32" in service
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK" in service
    assert "EnvironmentFile=-/etc/aegisscan/ddns-reconcile.env" in service
    assert "OnBootSec=20s" in timer
    assert "OnUnitInactiveSec=60s" in timer
    assert "RandomizedDelaySec=5s" in timer
    assert "WantedBy=timers.target" in timer


def test_host_bootstrap_scopes_internal_ingress_and_preserves_dns():
    script = (ROOT / "aegis-platform/scripts/production_host_bootstrap.sh").read_text()
    assert 'INTERNAL_CIDR="${AEGIS_INTERNAL_CIDR:-192.168.49.0/24}"' in script
    assert 'DNS_SERVICE_IP="${AEGIS_DNS_SERVICE_IP:-192.168.49.53}"' in script
    assert 'from "$INTERNAL_CIDR" to any port "$SSH_PORT" proto tcp' in script
    assert 'to "$DNS_SERVICE_IP" port 53 proto udp' in script
    assert 'to "$DNS_SERVICE_IP" port 53 proto tcp' in script
    assert 'from "$INTERNAL_CIDR" to any port 80 proto tcp' in script
    assert 'from "$INTERNAL_CIDR" to any port 443 proto tcp' in script
    assert 'ufw allow "$SSH_PORT/tcp"' not in script


def test_internal_dns_bootstrap_activates_and_verifies_address_before_bind_mutation():
    script = (ROOT / "aegis-platform/scripts/production_internal_dns_bootstrap.sh").read_text()
    netplan_render = 'cat >"$NETPLAN_FILE" <<EOF'
    apply_guard = 'if [ "$APPLY_NETWORK" -eq 1 ]; then'
    apply_call = "netplan apply"
    address_gate = 'grep -Fxq "$DNS_SERVICE_IP"'
    bind_mutation = "cat >/etc/bind/named.conf.options <<EOF"
    bind_restart = "systemctl restart named"

    assert 'APPLY_NETWORK="${AEGIS_NETPLAN_APPLY:-0}"' in script
    assert "AEGISSCAN_INTERNAL_DNS_BOOTSTRAP=PENDING_NETWORK_APPLY" in script

    assert script.index(netplan_render) < script.index(apply_guard)
    assert script.index(apply_guard) < script.index(apply_call)
    assert script.index(apply_call) < script.index(address_gate)
    assert script.index(address_gate) < script.index(bind_mutation)
    assert script.index(bind_mutation) < script.index(bind_restart)


def test_internal_dns_bootstrap_fails_closed_on_tsig_split_brain_and_keeps_backups():
    script = (ROOT / "aegis-platform/scripts/production_internal_dns_bootstrap.sh").read_text()
    assert 'tsig-keygen -a hmac-sha256 "$TSIG_NAME"' in script
    assert 'chmod 0600 "$RUNTIME_KEY_FILE"' in script
    assert 'cmp -s "$BIND_KEY_FILE" "$RUNTIME_KEY_FILE"' in script
    assert "refusing split-brain DDNS configuration" in script
    assert 'BACKUP_ROOT="${AEGIS_DNS_BACKUP_DIR:-/var/lib/aegisscan/backups/dns-config}"' in script
    assert 'cp -a "$candidate" "$BACKUP_ROOT/$safe_name.$STAMP"' in script
    assert 'backup_file "$NETPLAN_FILE"' in script
    assert "backup_file /etc/bind/named.conf.options" in script
    assert "backup_file /etc/bind/named.conf.local" in script
    assert 'backup_file "$BIND_INCLUDE"' in script
    assert 'backup_file "$RUNTIME_ENV_FILE"' in script
    assert 'secret "' not in script


def test_internal_dns_bootstrap_emits_runtime_environment_and_zone_coherently():
    script = (ROOT / "aegis-platform/scripts/production_internal_dns_bootstrap.sh").read_text()
    assert 'RUNTIME_ENV_FILE="/etc/aegisscan/ddns-reconcile.env"' in script
    assert 'AEGIS_DDNS_INTERFACE=$INTERFACE' in script
    assert 'AEGIS_DDNS_SERVER=$DNS_SERVICE_IP' in script
    assert 'AEGIS_DNS_SERVICE_IP=$DNS_SERVICE_IP' in script
    assert 'AEGIS_DDNS_NETWORK=$INTERNAL_CIDR' in script
    assert 'AEGIS_DDNS_FQDN=$FQDN_ABS' in script
    assert 'AEGIS_DDNS_ZONE=$ZONE_NAME.' in script
    assert 'AEGIS_DDNS_KEY=$RUNTIME_KEY_FILE' in script
    assert 'chmod 0600 "$RUNTIME_ENV_FILE"' in script
    assert 'zone "$ZONE_NAME"' in script
    assert 'grant $TSIG_NAME name $FQDN_ABS A;' in script
    assert 'ns1.$ZONE_NAME.' in script
    assert '$HOST_LABEL IN  A   $APP_IP' in script
    assert '-e "s|^IPAddressAllow=.*$|IPAddressAllow=$DNS_SERVICE_IP/32|"' in script


def _run_mac_independent_repair(tmp_path, *, source, actual_mac="00:50:56:31:fe:8b"):
    """Exercise the real embedded production repair against an isolated Netplan file."""
    script = (ROOT / "aegis-platform/scripts/production_internal_dns_bootstrap.sh").read_text()
    marker = """python3 - "$INSTALLER_NETPLAN_FILE" "$INTERFACE" "$HOST_MAC" <<'PYMAC'\n"""
    assert script.count(marker) == 1
    repair = script.split(marker, 1)[1].split("\nPYMAC\n", 1)[0]
    installer = tmp_path / "00-installer-config.yaml"
    installer.write_text(source)
    installer.chmod(0o600)
    proc = subprocess.run(
        [sys.executable, "-c", repair, str(installer), "ens33", actual_mac],
        text=True, capture_output=True, check=False,
    )
    return installer, proc


def test_dns_bootstrap_removes_stale_vmware_mac_match_but_keeps_dynamic_dhcp(tmp_path):
    source = """network:
  version: 2
  ethernets:
    ens33:
      dhcp4: true
      dhcp6: true
      match:
        macaddress: 00:0c:29:66:78:bf
      set-name: ens33
"""
    installer, attempt = _run_mac_independent_repair(tmp_path, source=source)
    assert attempt.returncode == 0, attempt.stderr
    rendered = yaml.safe_load(installer.read_text())
    nic = rendered["network"]["ethernets"]["ens33"]
    assert nic["dhcp4"] is True
    assert nic["dhcp6"] is True
    assert "match" not in nic
    assert "set-name" not in nic
    assert installer.stat().st_mode & 0o777 == 0o600
    saved = installer.read_bytes()
    # A second boot/bootstrap must not mutate the already-correct settings.
    installer, repeated = _run_mac_independent_repair(tmp_path, source=saved.decode())
    assert repeated.returncode == 0, repeated.stderr
    assert installer.read_bytes() == saved


def test_dns_bootstrap_rejects_unknown_mac_match_without_mutation(tmp_path):
    source = """network:
  version: 2
  ethernets:
    ens33:
      dhcp4: true
      match:
        macaddress: 00:0c:29:66:78:bf
        driver: e1000
      set-name: ens33
"""
    installer, attempt = _run_mac_independent_repair(tmp_path, source=source)
    assert attempt.returncode != 0
    assert installer.read_text() == source


def test_dns_bootstrap_requires_dhcp_and_rejects_interface_rename(tmp_path):
    source = """network:
  version: 2
  ethernets:
    ens33:
      dhcp4: false
      match:
        macaddress: 00:0c:29:66:78:bf
      set-name: another-interface
"""
    installer, attempt = _run_mac_independent_repair(tmp_path, source=source)
    assert attempt.returncode != 0
    assert installer.read_text() == source


def test_dns_bootstrap_repair_precedes_generation_and_is_safely_backed_up():
    script = (ROOT / "aegis-platform/scripts/production_internal_dns_bootstrap.sh").read_text()
    assert 'INSTALLER_NETPLAN_FILE=' in script
    assert script.index('backup_file "$INSTALLER_NETPLAN_FILE"') < script.index(
        'python3 - "$INSTALLER_NETPLAN_FILE" "$INTERFACE" "$HOST_MAC"')
    assert script.index("NETPLAN_DHCP_MAC_MATCH=removed-for-mac-independent-boot") < script.index(
        'cat >"$NETPLAN_FILE" <<EOF')
    assert script.index('cat >"$NETPLAN_FILE" <<EOF') < script.index("netplan generate")
    assert 'if [ "$APPLY_NETWORK" -eq 1 ]; then' in script
    # The DNS listener is stable; the application host address remains DHCP.
    assert 'addresses:\n        - $DNS_SERVICE_IP/32' in script


def _run_upstream_dns_guard(tmp_path, upstream):
    script = (ROOT / "aegis-platform/scripts/production_internal_dns_bootstrap.sh").read_text()
    anchor = '''python3 - "$UPSTREAM_DNS" "$DNS_SERVICE_IP" "$APP_IP" "$INTERNAL_CIDR" <<'PYUPSTREAM'\n'''
    assert script.count(anchor) == 1
    check = script.split(anchor, 1)[1].split("\nPYUPSTREAM\n", 1)[0]
    return subprocess.run(
        [sys.executable, "-c", check, upstream, "192.168.49.53", "192.168.49.136", "192.168.49.0/24"],
        text=True, capture_output=True, check=False,
    )


def test_dns_bootstrap_forwards_public_lookups_via_verified_dhcp_gateway(tmp_path):
    script = (ROOT / "aegis-platform/scripts/production_internal_dns_bootstrap.sh").read_text()
    assert 'ip -4 route show default dev "$INTERFACE"' in script
    assert 'UPSTREAM_DNS="${EXPLICIT_DNS_FORWARDER:-$GATEWAY_DNS}"' in script
    assert 'dig @"$UPSTREAM_DNS" github.com. A +short' in script
    assert "forwarders { $UPSTREAM_DNS; };" in script
    assert "forward only;" in script
    assert "dnssec-validation auto;" in script
    assert script.index("UPSTREAM_ANSWER=") < script.index('cat >"$NETPLAN_FILE" <<EOF')
    assert script.index("UPSTREAM_ANSWER=") < script.index('cat >/etc/bind/named.conf.options <<EOF')
    assert _run_upstream_dns_guard(tmp_path, "192.168.49.2").returncode == 0


def test_dns_bootstrap_rejects_self_referential_or_off_lan_forwarder(tmp_path):
    for upstream in ("192.168.49.53", "192.168.49.136", "8.8.8.8", "::1", "not-an-ip"):
        result = _run_upstream_dns_guard(tmp_path, upstream)
        assert result.returncode != 0, (upstream, result.stdout, result.stderr)
