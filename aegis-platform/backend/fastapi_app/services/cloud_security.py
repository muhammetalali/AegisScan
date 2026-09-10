#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from typing import Any, Callable, Iterable

from fastapi_app.services.cloud_target import CloudTarget, parse_cloud_target

SCHEMA = 'aegis.cloud-security.v1'
_MAX_CREDENTIAL_BYTES = 65536
_MAX_ITEMS = 1000
_MAX_AWS_REGIONS = 32
_MAX_AWS_BUCKETS = 200
_MAX_AZURE_NSGS = 500
_MAX_GCP_IAM_RESULTS = 1000


class CloudSecurityError(RuntimeError):
    pass


def _finding(
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    location: str,
    remediation: str,
    *,
    confidence: str = 'high',
    resource_kind: str = '',
    resource_name: str = '',
) -> dict[str, Any]:
    return {
        'kind': 'cloud-security-finding',
        'rule_id': rule_id,
        'title': title,
        'description': description,
        'severity': severity,
        'confidence': confidence,
        'category': 'cloud-security',
        'location': str(location)[:2048],
        'resource_kind': str(resource_kind)[:100],
        'resource_name': str(resource_name)[:500],
        'remediation': remediation,
    }


def _gap(provider: str, operation: str, code: str) -> dict[str, str]:
    return {
        'provider': provider,
        'operation': str(operation)[:200],
        'code': str(code or 'unavailable')[:100],
    }


def _load_credentials(path: str, target: CloudTarget) -> dict[str, Any]:
    credential_path = Path(path)
    try:
        metadata = credential_path.stat()
    except OSError as exc:
        raise CloudSecurityError('Cloud credential file is not available') from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise CloudSecurityError('Cloud credential path must be a regular file')
    if metadata.st_size <= 0 or metadata.st_size > _MAX_CREDENTIAL_BYTES:
        raise CloudSecurityError('Cloud credential file must be between 1 byte and 64 KiB')
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise CloudSecurityError('Cloud credential file must not be group/world accessible')
    try:
        data = json.loads(credential_path.read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CloudSecurityError('Cloud credential file must contain valid UTF-8 JSON') from exc
    if not isinstance(data, dict):
        raise CloudSecurityError('Cloud credential JSON must be an object')
    provider = str(data.get('provider') or '').strip().lower()
    if provider != target.provider:
        raise CloudSecurityError('Cloud credential provider does not match the authorized cloud target')
    return data


def _bounded_text(value: Any, *, maximum: int = 512) -> str:
    text = str(value or '').strip()
    if not text or len(text) > maximum or any(ch in text for ch in '\r\n\x00'):
        raise CloudSecurityError('Cloud credential contains an invalid field')
    return text


def _aws_credentials(data: dict[str, Any]) -> dict[str, str]:
    allowed = {'provider', 'access_key_id', 'secret_access_key', 'session_token', 'region'}
    if set(data) - allowed:
        raise CloudSecurityError('AWS credential contains unsupported fields')
    access_key = _bounded_text(data.get('access_key_id'), maximum=128)
    secret_key = _bounded_text(data.get('secret_access_key'), maximum=512)
    session_token = str(data.get('session_token') or '').strip()
    if len(session_token) > 8192 or any(ch in session_token for ch in '\r\n\x00'):
        raise CloudSecurityError('AWS session token is invalid')
    region = str(data.get('region') or 'us-east-1').strip().lower()
    if not region or len(region) > 64 or any(ch not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for ch in region):
        raise CloudSecurityError('AWS credential region is invalid')
    return {
        'access_key_id': access_key,
        'secret_access_key': secret_key,
        'session_token': session_token,
        'region': region,
    }


def _azure_credentials(data: dict[str, Any], target: CloudTarget) -> dict[str, str]:
    allowed = {'provider', 'tenant_id', 'client_id', 'client_secret', 'subscription_id'}
    if set(data) - allowed:
        raise CloudSecurityError('Azure credential contains unsupported fields')
    tenant_id = _bounded_text(data.get('tenant_id'), maximum=64).lower()
    client_id = _bounded_text(data.get('client_id'), maximum=64).lower()
    client_secret = _bounded_text(data.get('client_secret'), maximum=4096)
    subscription_id = _bounded_text(data.get('subscription_id'), maximum=64).lower()
    try:
        import uuid
        tenant_id = str(uuid.UUID(tenant_id))
        client_id = str(uuid.UUID(client_id))
        subscription_id = str(uuid.UUID(subscription_id))
    except ValueError as exc:
        raise CloudSecurityError('Azure tenant, client, and subscription IDs must be UUIDs') from exc
    if subscription_id != target.identifier:
        raise CloudSecurityError('Azure credential subscription does not match the authorized cloud target')
    return {
        'tenant_id': tenant_id,
        'client_id': client_id,
        'client_secret': client_secret,
        'subscription_id': subscription_id,
    }


def _gcp_credentials(data: dict[str, Any]) -> dict[str, Any]:
    allowed = {'provider', 'project_id', 'service_account'}
    if set(data) - allowed:
        raise CloudSecurityError('GCP credential contains unsupported fields')
    project_id = _bounded_text(data.get('project_id'), maximum=63).lower()
    service_account = data.get('service_account')
    if not isinstance(service_account, dict):
        raise CloudSecurityError('GCP credential requires a service_account JSON object')
    required = {'type', 'project_id', 'private_key_id', 'private_key', 'client_email', 'client_id', 'token_uri'}
    if not required <= set(service_account):
        raise CloudSecurityError('GCP service-account credential is incomplete')
    if str(service_account.get('type') or '') != 'service_account':
        raise CloudSecurityError('GCP credential type must be service_account')
    if str(service_account.get('project_id') or '').strip().lower() != project_id:
        raise CloudSecurityError('GCP service-account project metadata does not match credential project_id')
    return {'project_id': project_id, 'service_account': service_account}


def _port_range_exposes_admin(start: Any, end: Any) -> bool:
    try:
        low, high = int(start), int(end)
    except (TypeError, ValueError):
        return False
    return any(low <= port <= high for port in (22, 3389))


def _aws_sg_findings(groups: Iterable[Any], region: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for group in list(groups)[:_MAX_ITEMS]:
        if not isinstance(group, dict):
            continue
        group_id = str(group.get('GroupId') or group.get('GroupName') or 'unknown')[:255]
        for permission in group.get('IpPermissions') or []:
            if not isinstance(permission, dict):
                continue
            sources = [str(item.get('CidrIp') or '') for item in permission.get('IpRanges') or [] if isinstance(item, dict)]
            sources += [str(item.get('CidrIpv6') or '') for item in permission.get('Ipv6Ranges') or [] if isinstance(item, dict)]
            if not {'0.0.0.0/0', '::/0'} & set(sources):
                continue
            protocol = str(permission.get('IpProtocol') or '')
            all_traffic = protocol == '-1'
            admin = _port_range_exposes_admin(permission.get('FromPort'), permission.get('ToPort'))
            if not all_traffic and not admin:
                continue
            findings.append(_finding(
                'cloud.aws.security-group.world-admin-or-all',
                'AWS security group exposes administrative or all traffic to the Internet',
                'An ingress rule allows 0.0.0.0/0 or ::/0 to all protocols or an administrative port.',
                'high',
                f'aws://ec2/{region}/security-group/{group_id}',
                'Restrict ingress to explicitly required source networks and ports; remove world-open administrative access.',
                resource_kind='aws.ec2.security-group',
                resource_name=group_id,
            ))
    return findings


def _aws_collect(target: CloudTarget, data: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, str]]]:
    values = _aws_credentials(data)
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import ClientError
    except ImportError as exc:
        raise CloudSecurityError('AWS SDK is not installed') from exc
    session = boto3.Session(
        aws_access_key_id=values['access_key_id'],
        aws_secret_access_key=values['secret_access_key'],
        aws_session_token=values['session_token'] or None,
        region_name=values['region'],
    )
    config = Config(retries={'max_attempts': 3, 'mode': 'standard'}, connect_timeout=5, read_timeout=20)
    identity = session.client('sts', config=config).get_caller_identity()
    account_id = str(identity.get('Account') or '')
    if account_id != target.identifier:
        raise CloudSecurityError('AWS credential identity does not match the authorized account target')
    principal = str(identity.get('Arn') or '')[:1000]
    findings: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = []
    counts = {'regions': 0, 'security_groups': 0, 'buckets': 0}

    iam = session.client('iam', config=config)
    try:
        summary = iam.get_account_summary().get('SummaryMap') or {}
        if int(summary.get('AccountAccessKeysPresent') or 0) > 0:
            findings.append(_finding(
                'cloud.aws.root-access-key-present', 'AWS root account has an access key',
                'The AWS account summary reports one or more root-account access keys.', 'critical',
                f'aws://{account_id}/root', 'Remove root access keys and use least-privilege IAM roles with short-lived credentials.',
                resource_kind='aws.iam.root', resource_name='root',
            ))
        if int(summary.get('AccountMFAEnabled') or 0) == 0:
            findings.append(_finding(
                'cloud.aws.root-mfa-disabled', 'AWS root account MFA is not enabled',
                'The AWS account summary reports that MFA is not enabled for the root account.', 'high',
                f'aws://{account_id}/root', 'Enable phishing-resistant MFA for the root account and securely protect recovery paths.',
                resource_kind='aws.iam.root', resource_name='root',
            ))
    except ClientError as exc:
        gaps.append(_gap('aws', 'iam.get_account_summary', exc.response.get('Error', {}).get('Code', 'ClientError')))

    discovery = session.client('ec2', region_name=values['region'], config=config)
    try:
        regions = [str(row.get('RegionName') or '') for row in discovery.describe_regions(AllRegions=False).get('Regions') or []]
        regions = [region for region in regions if region][:_MAX_AWS_REGIONS]
    except ClientError as exc:
        gaps.append(_gap('aws', 'ec2.describe_regions', exc.response.get('Error', {}).get('Code', 'ClientError')))
        regions = [values['region']]
    counts['regions'] = len(regions)
    for region in regions:
        client = session.client('ec2', region_name=region, config=config)
        groups: list[dict[str, Any]] = []
        token: str | None = None
        try:
            for _ in range(10):
                kwargs: dict[str, Any] = {'MaxResults': 1000}
                if token:
                    kwargs['NextToken'] = token
                page = client.describe_security_groups(**kwargs)
                groups.extend(item for item in page.get('SecurityGroups') or [] if isinstance(item, dict))
                if len(groups) >= _MAX_ITEMS:
                    groups = groups[:_MAX_ITEMS]
                    break
                token = str(page.get('NextToken') or '') or None
                if not token:
                    break
            counts['security_groups'] += len(groups)
            findings.extend(_aws_sg_findings(groups, region))
        except ClientError as exc:
            gaps.append(_gap('aws', f'ec2.describe_security_groups:{region}', exc.response.get('Error', {}).get('Code', 'ClientError')))

    s3 = session.client('s3', config=config)
    try:
        buckets = list(s3.list_buckets().get('Buckets') or [])[:_MAX_AWS_BUCKETS]
        counts['buckets'] = len(buckets)
        for bucket in buckets:
            name = str(bucket.get('Name') or '')
            if not name:
                continue
            try:
                block = s3.get_public_access_block(Bucket=name).get('PublicAccessBlockConfiguration') or {}
                enabled = all(block.get(key) is True for key in (
                    'BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'
                ))
            except ClientError as exc:
                code = str(exc.response.get('Error', {}).get('Code') or 'ClientError')
                if code in {'NoSuchPublicAccessBlockConfiguration', 'NoSuchPublicAccessBlock'}:
                    enabled = False
                else:
                    gaps.append(_gap('aws', f's3.get_public_access_block:{name}', code))
                    continue
            if not enabled:
                findings.append(_finding(
                    'cloud.aws.s3.public-access-block-incomplete', 'S3 bucket public access block is incomplete',
                    'The bucket does not enforce all four S3 public-access-block controls.', 'high',
                    f'aws://s3/{name}', 'Enable all S3 public-access-block settings and review bucket/access-point policies.',
                    resource_kind='aws.s3.bucket', resource_name=name,
                ))
    except ClientError as exc:
        gaps.append(_gap('aws', 's3.list_buckets', exc.response.get('Error', {}).get('Code', 'ClientError')))
    return {'account_id': account_id, 'principal': principal, **counts}, findings, gaps


def _azure_rule_sources(rule: Any) -> set[str]:
    values = {str(getattr(rule, 'source_address_prefix', '') or '')}
    values.update(str(value) for value in (getattr(rule, 'source_address_prefixes', None) or []))
    return {value.lower() for value in values if value}


def _azure_rule_ports(rule: Any) -> set[str]:
    values = {str(getattr(rule, 'destination_port_range', '') or '')}
    values.update(str(value) for value in (getattr(rule, 'destination_port_ranges', None) or []))
    return {value.lower() for value in values if value}


def _azure_nsg_findings(nsgs: Iterable[Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    world = {'*', 'internet', '0.0.0.0/0', '::/0'}
    for nsg in list(nsgs)[:_MAX_AZURE_NSGS]:
        nsg_id = str(getattr(nsg, 'id', '') or '')[:2048]
        nsg_name = str(getattr(nsg, 'name', '') or 'unknown')[:500]
        rules = list(getattr(nsg, 'security_rules', None) or [])
        for rule in rules:
            if str(getattr(rule, 'direction', '') or '').lower() != 'inbound':
                continue
            if str(getattr(rule, 'access', '') or '').lower() != 'allow':
                continue
            if not (_azure_rule_sources(rule) & world):
                continue
            ports = _azure_rule_ports(rule)
            unsafe = '*' in ports or '22' in ports or '3389' in ports
            if not unsafe:
                for value in ports:
                    if '-' in value:
                        left, _, right = value.partition('-')
                        if _port_range_exposes_admin(left, right):
                            unsafe = True
                            break
            if not unsafe:
                continue
            rule_name = str(getattr(rule, 'name', '') or 'unnamed')[:500]
            findings.append(_finding(
                'cloud.azure.nsg.world-admin-or-all', 'Azure NSG allows Internet-wide administrative or all-port ingress',
                'An inbound Allow rule accepts Internet-wide sources for all ports or an administrative port.', 'high',
                f'{nsg_id}/securityRules/{rule_name}' if nsg_id else rule_name,
                'Restrict NSG ingress sources and destination ports to the minimum required ranges and services.',
                resource_kind='azure.network.security-rule', resource_name=f'{nsg_name}/{rule_name}',
            ))
    return findings


def _azure_collect(target: CloudTarget, data: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, str]]]:
    values = _azure_credentials(data, target)
    try:
        from azure.core.exceptions import HttpResponseError
        from azure.identity import ClientSecretCredential
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
    except ImportError as exc:
        raise CloudSecurityError('Azure SDK dependencies are not installed') from exc
    credential = ClientSecretCredential(
        tenant_id=values['tenant_id'], client_id=values['client_id'], client_secret=values['client_secret']
    )
    subscription_client = SubscriptionClient(credential)
    try:
        subscription = subscription_client.subscriptions.get(values['subscription_id'])
    except HttpResponseError as exc:
        raise CloudSecurityError(f'Azure subscription identity verification failed ({type(exc).__name__})') from exc
    actual = str(getattr(subscription, 'subscription_id', '') or '').lower()
    if actual != target.identifier:
        raise CloudSecurityError('Azure credential identity does not match the authorized subscription target')
    gaps: list[dict[str, str]] = []
    findings: list[dict[str, Any]] = []
    resource_client = ResourceManagementClient(credential, values['subscription_id'])
    groups: list[Any] = []
    resources: list[Any] = []
    try:
        groups = list(resource_client.resource_groups.list())[:_MAX_ITEMS]
    except HttpResponseError as exc:
        gaps.append(_gap('azure', 'resource_groups.list', type(exc).__name__))
    try:
        resources = list(resource_client.resources.list())[:_MAX_ITEMS]
    except HttpResponseError as exc:
        gaps.append(_gap('azure', 'resources.list', type(exc).__name__))
    network = NetworkManagementClient(credential, values['subscription_id'])
    nsgs: list[Any] = []
    public_ips: list[Any] = []
    try:
        nsgs = list(network.network_security_groups.list_all())[:_MAX_AZURE_NSGS]
        findings.extend(_azure_nsg_findings(nsgs))
    except HttpResponseError as exc:
        gaps.append(_gap('azure', 'network_security_groups.list_all', type(exc).__name__))
    try:
        public_ips = list(network.public_ip_addresses.list_all())[:_MAX_ITEMS]
    except HttpResponseError as exc:
        gaps.append(_gap('azure', 'public_ip_addresses.list_all', type(exc).__name__))
    return {
        'subscription_id': actual,
        'tenant_id': values['tenant_id'],
        'client_id': values['client_id'],
        'resource_groups': len(groups),
        'resources': len(resources),
        'network_security_groups': len(nsgs),
        'public_ip_addresses': len(public_ips),
    }, findings, gaps


def _gcp_collect(target: CloudTarget, data: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, str]]]:
    values = _gcp_credentials(data)
    if values['project_id'] != target.identifier:
        raise CloudSecurityError('GCP credential project does not match the authorized cloud target')
    try:
        from google.api_core.exceptions import GoogleAPICallError, PermissionDenied
        from google.cloud import asset_v1
        from google.oauth2 import service_account
    except ImportError as exc:
        raise CloudSecurityError('Google Cloud SDK dependencies are not installed') from exc
    try:
        credentials = service_account.Credentials.from_service_account_info(
            values['service_account'], scopes=['https://www.googleapis.com/auth/cloud-platform.read-only']
        )
    except Exception as exc:
        raise CloudSecurityError('GCP service-account credential could not be constructed') from exc
    principal = str(getattr(credentials, 'service_account_email', '') or '')[:1000]
    if not principal:
        raise CloudSecurityError('GCP service-account identity is unavailable')
    client = asset_v1.AssetServiceClient(credentials=credentials)
    scope = f'projects/{target.identifier}'
    gaps: list[dict[str, str]] = []
    findings: list[dict[str, Any]] = []
    resource_count = 0
    try:
        pager = client.search_all_resources(request={'scope': scope, 'page_size': 100})
        for _ in pager:
            resource_count += 1
            if resource_count >= _MAX_ITEMS:
                break
    except (PermissionDenied, GoogleAPICallError) as exc:
        gaps.append(_gap('gcp', 'asset.search_all_resources', type(exc).__name__))
    iam_count = 0
    try:
        pager = client.search_all_iam_policies(request={'scope': scope, 'page_size': 100})
        for result in pager:
            iam_count += 1
            policy = getattr(result, 'policy', None)
            for binding in list(getattr(policy, 'bindings', None) or []):
                public = sorted({str(member) for member in (getattr(binding, 'members', None) or []) if str(member) in {'allUsers', 'allAuthenticatedUsers'}})
                if not public:
                    continue
                resource = str(getattr(result, 'resource', '') or '')[:2048]
                role = str(getattr(binding, 'role', '') or '')[:500]
                findings.append(_finding(
                    'cloud.gcp.public-iam-binding', 'GCP IAM policy grants access to a public principal',
                    f'An IAM binding grants {role or "a role"} to {", ".join(public)}.', 'high',
                    resource or scope,
                    'Remove allUsers/allAuthenticatedUsers bindings unless the public exposure is explicitly required and governed.',
                    resource_kind='gcp.iam.binding', resource_name=role,
                ))
            if iam_count >= _MAX_GCP_IAM_RESULTS:
                break
    except (PermissionDenied, GoogleAPICallError) as exc:
        gaps.append(_gap('gcp', 'asset.search_all_iam_policies', type(exc).__name__))
    return {
        'project_id': target.identifier,
        'principal': principal,
        'resources': resource_count,
        'iam_policy_results': iam_count,
    }, findings, gaps


_COLLECTORS: dict[str, Callable[[CloudTarget, dict[str, Any]], tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, str]]]]] = {
    'aws': _aws_collect,
    'azure': _azure_collect,
    'gcp': _gcp_collect,
}


def collect_cloud_posture(target_value: str, credential_file: str) -> dict[str, Any]:
    target = parse_cloud_target(target_value)
    data = _load_credentials(credential_file, target)
    identity, findings, gaps = _COLLECTORS[target.provider](target, data)
    summary = {
        'kind': 'cloud-security-summary',
        'provider': target.provider,
        'target': target.canonical,
        'identity_verified': True,
        'read_only': True,
        'credential_source': 'vault-materialized-file',
        'ambient_credentials_used': False,
        'inventory': identity,
        'coverage_gaps': gaps,
        'finding_count': len(findings),
    }
    return {
        'schema': SCHEMA,
        'provider': target.provider,
        'target': target.canonical,
        'observations': [summary, *findings],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='AegisScan read-only multi-cloud posture analyzer')
    parser.add_argument('target', help='Canonical cloud scope: aws://ACCOUNT, azure://SUBSCRIPTION_UUID, or gcp://PROJECT_ID')
    parser.add_argument('--credentials-file', required=True, help='Worker-materialized 0600 Vault credential JSON')
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = collect_cloud_posture(args.target, args.credentials_file)
    except (CloudSecurityError, ValueError) as exc:
        print(json.dumps({'schema': SCHEMA, 'error': str(exc)}, sort_keys=True, separators=(',', ':')))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
