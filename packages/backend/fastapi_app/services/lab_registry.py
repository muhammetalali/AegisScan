from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class CapabilityDescriptor:
    name: str
    kind: str
    status: str
    version_strategy: str
    executor: str | None
    evidence: bool
    authorization_required: bool
    sandbox_required: bool
    network_access: str
    destructive: bool
    inputs: dict[str, Any]
    outputs: list[str]


@dataclass(frozen=True)
class LabDescriptor:
    id: str
    name: str
    status: str
    purpose: str
    isolation: dict[str, Any]
    capabilities: tuple[str, ...]
    authorization: dict[str, Any]
    evidence: dict[str, Any]
    supported_targets: tuple[str, ...]


CAPABILITIES: dict[str, CapabilityDescriptor] = {
    "distribution.kali": CapabilityDescriptor(
        name="Kali Linux", kind="distribution", status="catalogued", version_strategy="rolling",
        executor="container", evidence=False, authorization_required=True, sandbox_required=True,
        network_access="controlled-egress", destructive=False,
        inputs={"architecture": ["amd64", "arm64"]}, outputs=["tool_environment"],
    ),
    "network.nmap": CapabilityDescriptor(
        name="Nmap", kind="network_tool", status="implemented", version_strategy="container-pinned",
        executor="services.engine_adapters.execute_engine -> network_lab_executor -> lab-agent",
        evidence=True, authorization_required=True, sandbox_required=True,
        network_access="controlled-egress", destructive=False,
        inputs={"targets": ["ip", "cidr", "hostname"], "profiles": ["connect-discovery", "service-enumeration"]},
        outputs=["raw_xml", "services", "ports", "host_observations"],
    ),
    "network.masscan": CapabilityDescriptor(
        name="Masscan", kind="network_tool", status="implemented", version_strategy="container-pinned",
        executor="services.engine_adapters.execute_engine -> network_lab_executor -> lab-agent",
        evidence=True, authorization_required=True, sandbox_required=True,
        network_access="controlled-egress", destructive=False,
        inputs={"targets": ["ip", "cidr"], "profiles": ["low-rate-discovery"]},
        outputs=["raw_output", "open_port_observations"],
    ),
    "web.zap": CapabilityDescriptor(name="OWASP ZAP", kind="web_tool", status="planned", version_strategy="container-pinned", executor=None, evidence=True, authorization_required=True, sandbox_required=True, network_access="controlled-egress", destructive=False, inputs={"targets": ["url"], "profiles": ["baseline", "authenticated"]}, outputs=["alerts", "http_evidence"]),
    "identity.bloodhound": CapabilityDescriptor(name="BloodHound CE", kind="identity_tool", status="planned", version_strategy="container-pinned", executor=None, evidence=True, authorization_required=True, sandbox_required=True, network_access="lab-network", destructive=False, inputs={"targets": ["ad-lab"]}, outputs=["graph", "relationships", "attack_paths"]),
    "ad.impacket": CapabilityDescriptor(name="Impacket", kind="identity_toolkit", status="planned", version_strategy="container-pinned", executor=None, evidence=True, authorization_required=True, sandbox_required=True, network_access="lab-network", destructive=True, inputs={"targets": ["ad-lab"]}, outputs=["protocol_observations", "command_evidence"]),
    "ad.netexec": CapabilityDescriptor(name="NetExec", kind="identity_toolkit", status="planned", version_strategy="container-pinned", executor=None, evidence=True, authorization_required=True, sandbox_required=True, network_access="lab-network", destructive=True, inputs={"targets": ["ad-lab"]}, outputs=["session_observations", "protocol_results"]),
    "ad.samba": CapabilityDescriptor(name="Samba AD lab services", kind="identity_platform", status="planned", version_strategy="pinned", executor=None, evidence=True, authorization_required=True, sandbox_required=True, network_access="isolated-lab-network", destructive=False, inputs={"topology": ["single-domain", "multi-domain"]}, outputs=["directory_state", "policy_state"]),
}

LABS: dict[str, LabDescriptor] = {
    "network-lab": LabDescriptor(
        id="network-lab", name="AegisScan Network Validation Lab", status="ready-to-provision",
        purpose="Isolated network discovery and service observation using a controlled Kali-based toolbox.",
        isolation={"containerized": True, "privileged": False, "network_mode": "bridge", "capabilities": ["NET_RAW"], "host_mounts": False, "default_enabled": False, "profile": "security-lab"},
        capabilities=("distribution.kali", "network.nmap", "network.masscan"),
        authorization={"required": True, "target_allowlist_required": True, "approval_before_external_scan": True, "default_scope": "explicit-target-only"},
        evidence={"raw_tool_output_required": True, "execution_metadata_required": True, "target_and_scope_recorded": True, "synthetic_results_allowed": False},
        supported_targets=("ip", "cidr", "hostname"),
    )
}


def capability_catalog() -> list[dict[str, Any]]:
    return [asdict(item) for item in CAPABILITIES.values()]


def capability_detail(capability_id: str) -> dict[str, Any] | None:
    item = CAPABILITIES.get(capability_id)
    return asdict(item) if item else None


def lab_catalog() -> list[dict[str, Any]]:
    return [asdict(item) for item in LABS.values()]


def lab_detail(lab_id: str) -> dict[str, Any] | None:
    item = LABS.get(lab_id)
    if not item:
        return None
    data = asdict(item)
    data["capability_details"] = [asdict(CAPABILITIES[name]) for name in item.capabilities if name in CAPABILITIES]
    return data


def lab_readiness(lab_id: str) -> dict[str, Any]:
    lab = LABS.get(lab_id)
    if not lab:
        return {"lab_id": lab_id, "readiness": "not_found"}
    capability_states = {name: {"status": CAPABILITIES[name].status, "executor": CAPABILITIES[name].executor, "ready": CAPABILITIES[name].status in {"implemented", "ready"}} for name in lab.capabilities}
    return {"lab_id": lab_id, "readiness": "ready-to-provision" if lab.status == "ready-to-provision" else lab.status, "provisioning_profile": lab.isolation.get("profile"), "capabilities": capability_states, "authorization": lab.authorization, "evidence": lab.evidence}


def lab_snapshot() -> dict[str, Any]:
    return {"labs": lab_catalog(), "capabilities": capability_catalog(), "policy": {"synthetic_results": False, "external_target_requires_authorization": True, "tool_output_must_be_preserved": True, "execution_provenance_required": True}}
