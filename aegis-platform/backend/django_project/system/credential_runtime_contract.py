from __future__ import annotations

from django_project.system.credential_models import CredentialAccess, CredentialSecret


def credential_vault_contract() -> dict[str, object]:
    """Static contract consumed by runtime gates without exposing secret values."""
    secret_fields = {field.name for field in CredentialSecret._meta.fields}
    access_fields = {field.name for field in CredentialAccess._meta.fields}
    return {
        'credential_model': CredentialSecret.__name__,
        'access_model': CredentialAccess.__name__,
        'secret_never_returned_fields': sorted({'encrypted_secret', 'secret_fingerprint'} & secret_fields),
        'reference_field': 'id',
        'ledger_fields': sorted({'credential', 'project', 'actor', 'operation', 'result', 'purpose'} & access_fields),
        'append_only_ledger': True,
    }
