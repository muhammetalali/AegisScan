from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

CloudProvider = Literal['aws', 'azure', 'gcp']

_AWS_ACCOUNT_RE = re.compile(r'^[0-9]{12}$')
_GCP_PROJECT_RE = re.compile(r'^[a-z][a-z0-9-]{4,28}[a-z0-9]$')


@dataclass(frozen=True)
class CloudTarget:
    provider: CloudProvider
    identifier: str

    @property
    def canonical(self) -> str:
        return f'{self.provider}://{self.identifier}'

    @property
    def scope_key(self) -> str:
        return {
            'aws': 'account_id',
            'azure': 'subscription_id',
            'gcp': 'project_id',
        }[self.provider]


def parse_cloud_target(value: str) -> CloudTarget:
    raw = str(value or '').strip()
    if not raw or len(raw) > 256 or any(ch in raw for ch in '\r\n\x00'):
        raise ValueError('Cloud target is invalid')
    parsed = urlsplit(raw)
    provider = parsed.scheme.lower()
    if provider not in {'aws', 'azure', 'gcp'}:
        raise ValueError('Cloud target provider must be aws, azure, or gcp')
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError('Cloud target contains an invalid port') from exc
    if parsed.username or parsed.password or port is not None:
        raise ValueError('Cloud target must not contain credentials or a port')
    if parsed.path not in {'', '/'} or parsed.query or parsed.fragment:
        raise ValueError('Cloud target must contain only provider and scope identifier')
    identifier = (parsed.hostname or '').strip().lower()
    if provider == 'aws':
        if not _AWS_ACCOUNT_RE.fullmatch(identifier):
            raise ValueError('AWS cloud target must contain a 12-digit account ID')
    elif provider == 'azure':
        try:
            identifier = str(uuid.UUID(identifier))
        except ValueError as exc:
            raise ValueError('Azure cloud target must contain a subscription UUID') from exc
    else:
        if not _GCP_PROJECT_RE.fullmatch(identifier):
            raise ValueError('GCP cloud target must contain a canonical project ID')
    return CloudTarget(provider=provider, identifier=identifier)  # type: ignore[arg-type]


def canonical_cloud_target(value: str) -> str:
    return parse_cloud_target(value).canonical
