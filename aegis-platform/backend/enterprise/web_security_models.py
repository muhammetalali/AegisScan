from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class _ImmutableQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise RuntimeError('immutable security records cannot be updated')

    def delete(self):
        raise RuntimeError('immutable security records cannot be deleted')


class _ImmutableManager(models.Manager):
    def get_queryset(self):
        return _ImmutableQuerySet(self.model, using=self._db)


class SecurityGraphNode(models.Model):
    class Plane(models.TextChoices):
        APPLICATION = 'application', 'Application'
        IDENTITY = 'identity', 'Identity'
        ATTACK_SURFACE = 'attack_surface', 'Attack Surface'
        ADVERSARY = 'adversary', 'Adversary'
        DETECTION = 'detection', 'Detection'
        RISK = 'risk', 'Risk'
        GOVERNANCE = 'governance', 'Governance'

    class Kind(models.TextChoices):
        PAGE = 'page', 'Page'
        ENDPOINT = 'endpoint', 'Endpoint'
        CHANNEL = 'channel', 'Channel'
        GRAPHQL_OPERATION = 'graphql_operation', 'GraphQL Operation'
        GRAPHQL_TYPE = 'graphql_type', 'GraphQL Type'
        GRAPHQL_FIELD = 'graphql_field', 'GraphQL Field'
        GRAPHQL_ARGUMENT = 'graphql_argument', 'GraphQL Argument'
        WEBSOCKET_CHANNEL = 'websocket_channel', 'WebSocket Channel'
        IDENTITY = 'identity', 'Identity'
        SESSION = 'session', 'Session'
        ROLE = 'role', 'Role'
        TENANT = 'tenant', 'Tenant'
        RESOURCE = 'resource', 'Resource'
        POLICY = 'policy', 'Policy'
        OBSERVATION = 'observation', 'Observation'
        EVIDENCE = 'evidence', 'Evidence'
        FINDING = 'finding', 'Finding'
        ATTACK_CHAIN = 'attack_chain', 'Attack Chain'
        DETECTION = 'detection', 'Detection'
        RISK = 'risk', 'Risk'
        CONTROL = 'control', 'Control'
        REMEDIATION = 'remediation', 'Remediation'
        REVALIDATION = 'revalidation', 'Revalidation'
        SERVICE = 'service', 'Service'
        CACHE = 'cache', 'Cache'
        REVERSE_PROXY = 'reverse_proxy', 'Reverse Proxy'
        DATABASE = 'database', 'Database'
        EXTERNAL_SERVICE = 'external_service', 'External Service'
        THREAT = 'threat', 'Threat'
        TTP = 'ttp', 'ATT&CK TTP'
        ASSET = 'asset', 'Asset'
        CAPABILITY = 'capability', 'Capability'
        TRUST_BOUNDARY = 'trust_boundary', 'Trust Boundary'
        DATA_FLOW = 'data_flow', 'Data Flow'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='security_graph_nodes')
    plane = models.CharField(max_length=32, choices=Plane.choices, default=Plane.APPLICATION)
    kind = models.CharField(max_length=40, choices=Kind.choices)
    external_ref = models.CharField(max_length=500)
    label = models.CharField(max_length=300)
    protocol = models.CharField(max_length=32, blank=True)
    tenant_ref = models.CharField(max_length=255, blank=True)
    properties = models.JSONField(default=dict, blank=True)
    provenance = models.JSONField(default=dict, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['project', 'external_ref'],
                name='uniq_secgraph_project_ref',
            ),
        ]
        indexes = [
            models.Index(fields=['project', 'plane', 'kind'], name='idx_secgraph_project_kind'),
            models.Index(fields=['project', 'tenant_ref'], name='idx_secgraph_tenant'),
        ]


class SecurityGraphEdge(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='security_graph_edges')
    source = models.ForeignKey(SecurityGraphNode, on_delete=models.CASCADE, related_name='security_outgoing')
    target = models.ForeignKey(SecurityGraphNode, on_delete=models.CASCADE, related_name='security_incoming')
    relation = models.CharField(max_length=80)
    evidence_refs = models.JSONField(default=list, blank=True)
    properties = models.JSONField(default=dict, blank=True)
    provenance = models.JSONField(default=dict, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['project', 'source', 'target', 'relation'],
                name='uniq_secgraph_project_edge',
            ),
        ]
        indexes = [
            models.Index(fields=['project', 'relation'], name='idx_secedge_project_rel'),
        ]

    def clean(self):
        if self.source_id and self.source.project_id != self.project_id:
            raise ValidationError('security graph edge source must belong to the same project')
        if self.target_id and self.target.project_id != self.project_id:
            raise ValidationError('security graph edge target must belong to the same project')

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class AuthorizationPolicyManifest(models.Model):
    class Source(models.TextChoices):
        OPERATOR_DECLARED = 'operator_declared', 'Operator Declared'
        SOURCE_ANNOTATION = 'source_annotation', 'Source Annotation'
        APPLICATION_RBAC = 'application_rbac', 'Application RBAC'
        OAUTH_SCOPE = 'oauth_scope', 'OAuth Scope'
        OPENAPI_EXTENSION = 'openapi_extension', 'OpenAPI Extension'
        OBSERVED_BASELINE = 'observed_baseline', 'Observed Baseline'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.PROTECT, related_name='authorization_policy_manifests')
    identity_type = models.CharField(max_length=80)
    role = models.CharField(max_length=120, blank=True)
    tenant_ref = models.CharField(max_length=255, blank=True)
    endpoint = models.CharField(max_length=700)
    method = models.CharField(max_length=16)
    operation = models.CharField(max_length=160, blank=True)
    resource_type = models.CharField(max_length=160, blank=True)
    allowed = models.BooleanField()
    ownership_rule = models.CharField(max_length=160, blank=True)
    tenant_rule = models.CharField(max_length=160, blank=True)
    sensitive_operation = models.BooleanField(default=False)
    required_scopes = models.JSONField(default=list, blank=True)
    conditions = models.JSONField(default=dict, blank=True)
    policy_source = models.CharField(max_length=40, choices=Source.choices)
    provenance = models.JSONField(default=dict, blank=True)
    confidence = models.FloatField(default=1.0)
    last_verified_at = models.DateTimeField(null=True, blank=True)
    version = models.PositiveIntegerField(default=1)
    canonical_sha256 = models.CharField(max_length=64, unique=True, editable=False)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='authorization_policy_manifests')
    created_at = models.DateTimeField(auto_now_add=True)
    objects = _ImmutableManager()

    class Meta:
        ordering = ['-created_at', '-id']
        indexes = [
            models.Index(fields=['project', 'endpoint', 'method'], name='idx_authpol_endpoint'),
            models.Index(fields=['project', 'role', 'tenant_ref'], name='idx_authpol_role_tenant'),
        ]

    def clean(self):
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValidationError('confidence must be between 0 and 1')

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('authorization policy manifests are immutable')
        self.method = (self.method or '*').upper()
        self.full_clean()
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('authorization policy manifests are immutable')


class ExecutionBudgetProfile(models.Model):
    class Environment(models.TextChoices):
        PRODUCTION = 'production', 'Production'
        STAGING = 'staging', 'Staging'
        DEVELOPMENT = 'development', 'Development'
        DIGITAL_TWIN = 'digital_twin', 'Digital Twin'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.PROTECT, related_name='execution_budget_profiles')
    name = models.CharField(max_length=120)
    environment = models.CharField(max_length=20, choices=Environment.choices)
    allowed_capabilities = models.JSONField(default=list, blank=True)
    max_requests = models.PositiveIntegerField(default=1000)
    network_io_bytes = models.BigIntegerField(default=104857600)
    browser_sessions = models.PositiveIntegerField(default=2)
    identities = models.PositiveIntegerField(default=5)
    object_mutations = models.PositiveIntegerField(default=0)
    parallelism = models.PositiveIntegerField(default=4)
    cpu_seconds = models.PositiveIntegerField(default=300)
    memory_mb = models.PositiveIntegerField(default=1024)
    duration_seconds = models.PositiveIntegerField(default=900)
    state_changes = models.BooleanField(default=False)
    destructive_operations = models.BooleanField(default=False)
    state_change_policy = models.CharField(max_length=80, default='deny')
    version = models.PositiveIntegerField(default=1)
    canonical_sha256 = models.CharField(max_length=64, unique=True, editable=False)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='execution_budget_profiles')
    created_at = models.DateTimeField(auto_now_add=True)
    objects = _ImmutableManager()

    class Meta:
        ordering = ['-created_at', '-id']
        indexes = [
            models.Index(fields=['project', 'environment', '-created_at'], name='idx_budget_project_env'),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('execution budget profiles are immutable')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('execution budget profiles are immutable')


class ProviderApprovalRecord(models.Model):
    class Status(models.TextChoices):
        APPROVED = 'approved', 'Approved'
        EXPERIMENTAL = 'experimental', 'Experimental'
        RESTRICTED = 'restricted', 'Restricted'
        REJECTED = 'rejected', 'Rejected'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.PROTECT, related_name='provider_approval_records')
    provider_name = models.CharField(max_length=180)
    provider_version = models.CharField(max_length=120)
    status = models.CharField(max_length=20, choices=Status.choices)
    capability = models.CharField(max_length=180)
    manifest = models.JSONField(default=dict)
    rationale = models.TextField(blank=True)
    manifest_sha256 = models.CharField(max_length=64, editable=False)
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='provider_approval_records')
    created_at = models.DateTimeField(auto_now_add=True)
    objects = _ImmutableManager()

    class Meta:
        ordering = ['-created_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['project', 'provider_name', 'provider_version', 'capability', 'status', 'manifest_sha256'],
                name='uniq_provider_approval_dec',
            ),
        ]
        indexes = [
            models.Index(fields=['project', 'status'], name='idx_provider_project_state'),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('provider approval records are immutable')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('provider approval records are immutable')


class WebSecurityValidationRun(models.Model):
    class Kind(models.TextChoices):
        AUTHORIZATION_MATRIX = 'authorization_matrix', 'Authorization Matrix'
        NEGATIVE_PATH = 'negative_path', 'Negative Path'
        RESPONSE_COMPARISON = 'response_comparison', 'Response Comparison'
        WEBSOCKET_SECURITY = 'websocket_security', 'WebSocket Security'
        GRAPHQL_SECURITY = 'graphql_security', 'GraphQL Security'
        CROSS_PROTOCOL = 'cross_protocol', 'Cross-Protocol State'
        IDENTITY_PROTOCOL_SECURITY = 'identity_protocol_security', 'Identity Protocol Security'
        HTTP_PROTOCOL_SECURITY = 'http_protocol_security', 'HTTP Protocol Security'

    class Status(models.TextChoices):
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.PROTECT, related_name='web_security_validation_runs')
    kind = models.CharField(max_length=40, choices=Kind.choices)
    status = models.CharField(max_length=20, choices=Status.choices)
    contract_version = models.CharField(max_length=20, default='2.0')
    input_sha256 = models.CharField(max_length=64)
    summary = models.JSONField(default=dict, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='web_security_validation_runs')
    created_at = models.DateTimeField(auto_now_add=True)
    objects = _ImmutableManager()

    class Meta:
        ordering = ['-created_at', '-id']
        indexes = [
            models.Index(fields=['project', 'kind', '-created_at'], name='idx_webval_project_kind'),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('web security validation runs are immutable')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('web security validation runs are immutable')


class WebSecurityObservation(models.Model):
    class Decision(models.TextChoices):
        ALLOWED = 'allowed', 'Allowed'
        DENIED = 'denied', 'Denied'
        ERROR = 'error', 'Error'
        INDETERMINATE = 'indeterminate', 'Indeterminate'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    run = models.ForeignKey(WebSecurityValidationRun, on_delete=models.PROTECT, related_name='observations')
    policy = models.ForeignKey(AuthorizationPolicyManifest, on_delete=models.PROTECT, null=True, blank=True, related_name='observations')
    case_ref = models.CharField(max_length=255)
    identity_ref = models.CharField(max_length=255)
    identity_type = models.CharField(max_length=80)
    role = models.CharField(max_length=120, blank=True)
    tenant_ref = models.CharField(max_length=255, blank=True)
    resource_ref = models.CharField(max_length=255, blank=True)
    resource_tenant_ref = models.CharField(max_length=255, blank=True)
    endpoint = models.CharField(max_length=700)
    method = models.CharField(max_length=16)
    operation = models.CharField(max_length=160, blank=True)
    expected_allowed = models.BooleanField()
    observed_decision = models.CharField(max_length=20, choices=Decision.choices)
    passed = models.BooleanField()
    semantic = models.JSONField(default=dict)
    evidence_fingerprint = models.CharField(max_length=64, blank=True)
    reason = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    objects = _ImmutableManager()

    class Meta:
        ordering = ['created_at', 'id']
        indexes = [
            models.Index(fields=['run', 'passed'], name='idx_webobs_run_pass'),
            models.Index(fields=['identity_ref', 'resource_ref'], name='idx_webobs_identity_resource'),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('web security observations are immutable')
        self.method = (self.method or '*').upper()
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('web security observations are immutable')
