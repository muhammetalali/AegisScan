from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_systemd_ddns_contract_is_hardened_and_periodic():
    service = (ROOT / "aegis-platform/systemd/aegisscan-ddns-reconcile.service").read_text()
    timer = (ROOT / "aegis-platform/systemd/aegisscan-ddns-reconcile.timer").read_text()
    assert "NoNewPrivileges=yes" in service
    assert "ProtectSystem=strict" in service
    assert "IPAddressDeny=any" in service
    assert "IPAddressAllow=192.168.49.53/32" in service
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK" in service
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


def test_internal_dns_bootstrap_keeps_network_apply_explicit():
    script = (ROOT / "aegis-platform/scripts/production_internal_dns_bootstrap.sh").read_text()
    assert 'APPLY_NETWORK="${AEGIS_NETPLAN_APPLY:-0}"' in script
    assert 'if [ "$APPLY_NETWORK" -eq 1 ]; then' in script
    assert "NETPLAN_APPLY=PENDING" in script
    assert 'tsig-keygen -a hmac-sha256 "$TSIG_NAME"' in script
    assert 'chmod 0600 "$RUNTIME_KEY_FILE"' in script
    assert 'secret "' not in script
