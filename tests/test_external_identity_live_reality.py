from __future__ import annotations

import base64
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "aegis-platform" / "backend" / "scripts" / "external_identity_live_reality.py"
SPEC = importlib.util.spec_from_file_location("external_identity_live_reality", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)

LiveIdentityError = MODULE.LiveIdentityError


def test_oidc_metadata_requires_secure_code_pkce_and_asymmetric_signing():
    metadata = {
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
        "token_endpoint": "https://idp.example.com/oauth2/token",
        "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    jwks = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "key-1"}]}
    result = MODULE._validate_oidc_metadata(metadata, jwks, expected_issuer="https://idp.example.com")
    assert result["pkce_s256"] is True
    assert result["authorization_code_flow"] is True
    assert result["signing_key_count"] == 1

    bad = dict(metadata)
    bad["id_token_signing_alg_values_supported"] = ["none"]
    with pytest.raises(LiveIdentityError, match="alg=none"):
        MODULE._validate_oidc_metadata(bad, jwks, expected_issuer="https://idp.example.com")


def _certificate_xml() -> bytes:
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Aegis Test IdP")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    encoded = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    return f"""<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
      xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
      entityID="https://idp.example.com/saml">
      <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{encoded}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
      </IDPSSODescriptor>
    </EntityDescriptor>""".encode()


def test_saml_metadata_requires_https_sso_and_current_signing_certificate():
    result = MODULE._validate_saml_metadata(_certificate_xml())
    assert result["active_signing_certificate_count"] == 1
    assert len(result["signing_certificate_sha256"]) == 1


def test_scim_documents_require_real_service_config_and_resource_types():
    config = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "filter": {"supported": True},
        "authenticationSchemes": [{"type": "oauthbearertoken"}],
    }
    resources = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "Resources": [{
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
        }],
    }
    result = MODULE._validate_scim_documents(config, resources)
    assert result["resource_type_count"] == 1
    assert result["authentication_scheme_types"] == ["oauthbearertoken"]


def test_rejects_insecure_or_credential_bearing_urls():
    for url in (
        "http://idp.example.com/.well-known/openid-configuration",
        "https://user:password@idp.example.com/metadata",
        "https://idp.example.com/metadata#fragment",
    ):
        with pytest.raises(LiveIdentityError):
            MODULE._assert_https(url, "test endpoint")
