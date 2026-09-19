from pathlib import Path

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
    assert 'RUNTIME_ENV_FILE="${AEGIS_DDNS_ENV_FILE:-/etc/aegisscan/ddns-reconcile.env}"' in script
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
