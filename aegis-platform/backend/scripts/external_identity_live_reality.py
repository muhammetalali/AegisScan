#!/usr/bin/env python3
"""Read-only live validation for external enterprise identity providers."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from defusedxml import ElementTree as DefusedET

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 15
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
OIDC_STRONG_SIGNING_ALGORITHMS = {
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512", "EdDSA",
}
OIDC_SIGNING_KTYS = {"RSA", "EC", "OKP"}
SAML_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
XML_DS = "http://www.w3.org/2000/09/xmldsig#"
SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
SCIM_LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"


class LiveIdentityError(RuntimeError):
    pass


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _assert_https(value: str, label: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme.lower() != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise LiveIdentityError(f"{label} must be an absolute credential-free HTTPS URL")
    if parsed.fragment:
        raise LiveIdentityError(f"{label} must not contain a URL fragment")
    return value.strip()


def _session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": "AegisScan-External-Identity-Reality/1.0"})
    return session


def _fetch(
    session: requests.Session,
    url: str,
    *,
    verify: bool | str,
    bearer_token: str | None = None,
) -> tuple[bytes, str]:
    _assert_https(url, "live identity endpoint")
    headers: dict[str, str] = {
        "Accept": "application/json, application/samlmetadata+xml, application/xml, text/xml"
    }
    if bearer_token is not None:
        token = bearer_token.strip()
        if len(token) < 8 or any(ch in token for ch in "\r\n"):
            raise LiveIdentityError("SCIM bearer token is malformed")
        headers["Authorization"] = f"Bearer {token}"

    response = session.get(
        url,
        headers=headers,
        timeout=DEFAULT_TIMEOUT_SECONDS,
        verify=verify,
        allow_redirects=False,
    )
    if 300 <= response.status_code < 400:
        raise LiveIdentityError(f"live identity endpoint redirected unexpectedly: {response.status_code}")
    response.raise_for_status()

    content_length = response.headers.get("Content-Length", "").strip()
    if content_length.isdigit() and int(content_length) > MAX_RESPONSE_BYTES:
        raise LiveIdentityError("live identity response exceeds 2 MiB")
    content = response.content
    if not content or len(content) > MAX_RESPONSE_BYTES:
        raise LiveIdentityError("live identity response is empty or exceeds 2 MiB")
    return content, response.headers.get("Content-Type", "")


def _json_object(content: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LiveIdentityError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise LiveIdentityError(f"{label} must be a JSON object")
    return value


def _validate_oidc_metadata(
    metadata: dict[str, Any],
    jwks: dict[str, Any],
    *,
    expected_issuer: str,
) -> dict[str, Any]:
    expected_issuer = _assert_https(expected_issuer, "OIDC expected issuer")
    observed_issuer = str(metadata.get("issuer") or "")
    if observed_issuer != expected_issuer:
        raise LiveIdentityError("OIDC issuer does not exactly match the configured issuer")

    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        _assert_https(str(metadata.get(field) or ""), f"OIDC {field}")

    response_types = {str(v) for v in (metadata.get("response_types_supported") or [])}
    if "code" not in response_types:
        raise LiveIdentityError("OIDC provider does not advertise authorization-code response type")

    pkce_methods = {str(v) for v in (metadata.get("code_challenge_methods_supported") or [])}
    if "S256" not in pkce_methods:
        raise LiveIdentityError("OIDC provider does not advertise PKCE S256")

    signing_algs = {str(v) for v in (metadata.get("id_token_signing_alg_values_supported") or [])}
    if not signing_algs or "none" in {v.lower() for v in signing_algs}:
        raise LiveIdentityError("OIDC provider signing algorithm policy is absent or permits alg=none")
    if signing_algs.isdisjoint(OIDC_STRONG_SIGNING_ALGORITHMS):
        raise LiveIdentityError("OIDC provider does not advertise a supported asymmetric signing algorithm")

    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys:
        raise LiveIdentityError("OIDC JWKS does not contain signing keys")
    signing_keys = []
    for key in keys:
        if not isinstance(key, dict):
            continue
        if str(key.get("kty") or "") not in OIDC_SIGNING_KTYS:
            continue
        if str(key.get("use") or "sig") not in {"sig", ""}:
            continue
        key_ops = {str(v) for v in (key.get("key_ops") or [])}
        if key_ops and "verify" not in key_ops:
            continue
        if str(key.get("alg") or "").lower() == "none":
            continue
        signing_keys.append(key)
    if not signing_keys:
        raise LiveIdentityError("OIDC JWKS has no usable asymmetric verification key")

    return {
        "issuer_sha256": _sha256_text(observed_issuer),
        "authorization_endpoint_sha256": _sha256_text(str(metadata["authorization_endpoint"])),
        "token_endpoint_sha256": _sha256_text(str(metadata["token_endpoint"])),
        "jwks_uri_sha256": _sha256_text(str(metadata["jwks_uri"])),
        "signing_algorithms": sorted(signing_algs),
        "signing_key_count": len(signing_keys),
        "pkce_s256": True,
        "authorization_code_flow": True,
    }


def _validate_saml_metadata(content: bytes, *, now: datetime | None = None) -> dict[str, Any]:
    try:
        root = DefusedET.fromstring(content)
    except Exception as exc:
        raise LiveIdentityError("SAML metadata is not safe, well-formed XML") from exc

    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)

    if root.tag == f"{{{SAML_MD}}}EntityDescriptor":
        entity_descriptors = [root]
    elif root.tag == f"{{{SAML_MD}}}EntitiesDescriptor":
        entity_descriptors = list(root.findall(f".//{{{SAML_MD}}}EntityDescriptor"))
    else:
        raise LiveIdentityError("SAML metadata root is not EntityDescriptor/EntitiesDescriptor")

    idp_descriptors = []
    for entity in entity_descriptors:
        idp_descriptors.extend(entity.findall(f"./{{{SAML_MD}}}IDPSSODescriptor"))
    if not idp_descriptors:
        raise LiveIdentityError("SAML metadata does not contain an IdP SSO descriptor")

    sso_locations: list[str] = []
    cert_fingerprints: set[str] = set()
    active_certificates = 0
    for idp in idp_descriptors:
        for service in idp.findall(f"./{{{SAML_MD}}}SingleSignOnService"):
            location = str(service.attrib.get("Location") or "")
            sso_locations.append(_assert_https(location, "SAML SingleSignOnService Location"))
        for key_descriptor in idp.findall(f"./{{{SAML_MD}}}KeyDescriptor"):
            use = str(key_descriptor.attrib.get("use") or "")
            if use not in {"", "signing"}:
                continue
            for cert_node in key_descriptor.findall(f".//{{{XML_DS}}}X509Certificate"):
                encoded = "".join((cert_node.text or "").split())
                if not encoded:
                    continue
                try:
                    cert = x509.load_der_x509_certificate(base64.b64decode(encoded, validate=True))
                except Exception as exc:
                    raise LiveIdentityError("SAML metadata contains an invalid signing certificate") from exc
                cert_fingerprints.add(cert.fingerprint(hashes.SHA256()).hex())
                if cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
                    active_certificates += 1

    if not sso_locations:
        raise LiveIdentityError("SAML metadata contains no HTTPS SSO endpoint")
    if not cert_fingerprints or active_certificates < 1:
        raise LiveIdentityError("SAML metadata contains no currently valid signing certificate")

    entity_ids = sorted(
        str(entity.attrib.get("entityID") or "")
        for entity in entity_descriptors
        if str(entity.attrib.get("entityID") or "")
    )
    if not entity_ids:
        raise LiveIdentityError("SAML metadata does not expose an entityID")

    return {
        "entity_ids_sha256": [_sha256_text(value) for value in entity_ids],
        "sso_endpoint_sha256": sorted({_sha256_text(value) for value in sso_locations}),
        "signing_certificate_sha256": sorted(cert_fingerprints),
        "active_signing_certificate_count": active_certificates,
    }


def _validate_scim_documents(
    service_provider_config: dict[str, Any],
    resource_types: dict[str, Any],
) -> dict[str, Any]:
    config_schemas = {str(v) for v in (service_provider_config.get("schemas") or [])}
    if SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA not in config_schemas:
        raise LiveIdentityError("SCIM ServiceProviderConfig schema marker is missing")

    list_schemas = {str(v) for v in (resource_types.get("schemas") or [])}
    if SCIM_LIST_RESPONSE_SCHEMA not in list_schemas:
        raise LiveIdentityError("SCIM ResourceTypes response is not a SCIM ListResponse")
    resources = resource_types.get("Resources")
    if not isinstance(resources, list) or not resources:
        raise LiveIdentityError("SCIM ResourceTypes response has no resources")

    normalized_resources = []
    for item in resources:
        if not isinstance(item, dict):
            continue
        resource_id = str(item.get("id") or "")
        name = str(item.get("name") or "")
        endpoint = str(item.get("endpoint") or "")
        schema = str(item.get("schema") or "")
        if resource_id and name and endpoint and schema:
            normalized_resources.append({
                "id_sha256": _sha256_text(resource_id),
                "name_sha256": _sha256_text(name),
                "endpoint_sha256": _sha256_text(endpoint),
                "schema_sha256": _sha256_text(schema),
            })
    if not normalized_resources:
        raise LiveIdentityError("SCIM ResourceTypes contains no complete resource definition")

    authentication_schemes = []
    for item in service_provider_config.get("authenticationSchemes") or []:
        if isinstance(item, dict):
            auth_type = str(item.get("type") or "")
            if auth_type:
                authentication_schemes.append(auth_type)

    return {
        "resource_type_count": len(normalized_resources),
        "resource_types": normalized_resources,
        "authentication_scheme_types": sorted(set(authentication_schemes)),
        "patch_supported": bool((service_provider_config.get("patch") or {}).get("supported")),
        "filter_supported": bool((service_provider_config.get("filter") or {}).get("supported")),
    }


def run_live_validation(
    *,
    source_sha: str,
    oidc_discovery_url: str = "",
    oidc_expected_issuer: str = "",
    saml_metadata_url: str = "",
    scim_base_url: str = "",
    scim_bearer_token: str = "",
    ca_bundle: str = "",
) -> dict[str, Any]:
    if not SOURCE_SHA_RE.fullmatch(source_sha):
        raise LiveIdentityError("source SHA must be exactly 40 lowercase hexadecimal characters")

    verify: bool | str = True
    if ca_bundle:
        ca_path = Path(ca_bundle)
        if not ca_path.is_file() or ca_path.stat().st_size <= 0 or ca_path.stat().st_size > 2 * 1024 * 1024:
            raise LiveIdentityError("identity CA bundle is missing or invalid")
        verify = str(ca_path)

    configured: list[str] = []
    proof: dict[str, Any] = {
        "schema": "aegis.external-identity-live-proof.v1",
        "status": "success",
        "source_sha": source_sha,
        "read_only": True,
        "ambient_credentials_used": False,
        "configured_types": configured,
        "completed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }

    session = _session()
    try:
        if oidc_discovery_url or oidc_expected_issuer:
            if not oidc_discovery_url or not oidc_expected_issuer:
                raise LiveIdentityError("OIDC discovery URL and expected issuer must be configured together")
            discovery_url = _assert_https(oidc_discovery_url, "OIDC discovery URL")
            metadata_bytes, _ = _fetch(session, discovery_url, verify=verify)
            metadata = _json_object(metadata_bytes, "OIDC discovery document")
            jwks_url = _assert_https(str(metadata.get("jwks_uri") or ""), "OIDC jwks_uri")
            jwks_bytes, _ = _fetch(session, jwks_url, verify=verify)
            jwks = _json_object(jwks_bytes, "OIDC JWKS")
            oidc = _validate_oidc_metadata(metadata, jwks, expected_issuer=oidc_expected_issuer)
            oidc.update({"discovery_sha256": _sha256_bytes(metadata_bytes), "jwks_sha256": _sha256_bytes(jwks_bytes)})
            proof["oidc"] = oidc
            configured.append("oidc")

        if saml_metadata_url:
            metadata_url = _assert_https(saml_metadata_url, "SAML metadata URL")
            metadata_bytes, _ = _fetch(session, metadata_url, verify=verify)
            saml = _validate_saml_metadata(metadata_bytes)
            saml["metadata_sha256"] = _sha256_bytes(metadata_bytes)
            saml["metadata_url_sha256"] = _sha256_text(metadata_url)
            proof["saml"] = saml
            configured.append("saml")

        if scim_base_url or scim_bearer_token:
            if not scim_base_url or not scim_bearer_token:
                raise LiveIdentityError("SCIM base URL and bearer token must be configured together")
            base = _assert_https(scim_base_url, "SCIM base URL").rstrip("/")
            config_bytes, _ = _fetch(session, f"{base}/ServiceProviderConfig", verify=verify, bearer_token=scim_bearer_token)
            resource_types_bytes, _ = _fetch(session, f"{base}/ResourceTypes", verify=verify, bearer_token=scim_bearer_token)
            config = _json_object(config_bytes, "SCIM ServiceProviderConfig")
            resource_types = _json_object(resource_types_bytes, "SCIM ResourceTypes")
            scim = _validate_scim_documents(config, resource_types)
            scim.update({
                "base_url_sha256": _sha256_text(base),
                "service_provider_config_sha256": _sha256_bytes(config_bytes),
                "resource_types_sha256": _sha256_bytes(resource_types_bytes),
            })
            proof["scim"] = scim
            configured.append("scim")
    finally:
        session.close()

    if not configured:
        raise LiveIdentityError("at least one real OIDC, SAML, or SCIM provider binding is required")
    return proof


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--oidc-discovery-url", default="")
    parser.add_argument("--oidc-expected-issuer", default="")
    parser.add_argument("--saml-metadata-url", default="")
    parser.add_argument("--scim-base-url", default="")
    parser.add_argument("--scim-bearer-file", default="")
    parser.add_argument("--ca-bundle", default="")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    scim_token = ""
    if args.scim_bearer_file:
        token_path = Path(args.scim_bearer_file)
        if not token_path.is_file() or token_path.stat().st_size <= 0 or token_path.stat().st_size > 64 * 1024:
            raise SystemExit("SCIM bearer token file is missing or invalid")
        scim_token = token_path.read_text(encoding="utf-8").strip()

    try:
        proof = run_live_validation(
            source_sha=args.source_sha,
            oidc_discovery_url=args.oidc_discovery_url,
            oidc_expected_issuer=args.oidc_expected_issuer,
            saml_metadata_url=args.saml_metadata_url,
            scim_base_url=args.scim_base_url,
            scim_bearer_token=scim_token,
            ca_bundle=args.ca_bundle,
        )
    except (LiveIdentityError, requests.RequestException) as exc:
        print(f"EXTERNAL_IDENTITY_LIVE_FAIL: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(proof, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
