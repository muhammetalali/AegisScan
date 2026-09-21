import { z } from 'zod'

export const AgomContractVersionSchema = z.literal('agom.v1')
export const AgomActorLayerSchema = z.enum(['operate', 'govern', 'assure'])
export const AgomActionModeSchema = z.enum(['enabled', 'blocked', 'hidden'])
export const AgomGateStateSchema = z.enum(['pass', 'fail', 'blocked', 'not_applicable'])
export const AgomGateTypeSchema = z.enum([
  'authorization',
  'evidence',
  'validation',
  'publication',
  'closure',
  'expiry_review',
  'live_acceptance',
  'independent_verification',
])

export const AgomEntityRefSchema = z.object({
  entity_type: z.string().min(1),
  entity_id: z.string().min(1),
  tenant_id: z.string().nullable(),
  project_id: z.string().nullable(),
}).strict()

export const AgomProjectionSnapshotSchema = z.object({
  lifecycle: z.string().nullable(),
  outcome: z.string().nullable(),
  posture: z.string().nullable(),
  governance: z.string().nullable(),
  assurance: z.string().nullable(),
  version: z.number().int().nonnegative().nullable(),
}).strict()

export const AgomGateResultSchema = z.object({
  gate: AgomGateTypeSchema,
  state: AgomGateStateSchema,
  reason_code: z.string(),
  reason: z.string(),
  missing_requirements: z.array(z.string()),
  evidence_refs: z.array(z.string()),
  policy_version: z.string(),
  evaluated_at: z.string().nullable(),
}).strict()

export const AgomActionContractSchema = z.object({
  action_id: z.string().min(1),
  entity_type: z.string().min(1),
  intent: z.string().min(1),
  allowed_states: z.array(z.string()),
  actor_layers: z.array(AgomActorLayerSchema),
  allowed_roles: z.array(z.string()),
  required_responsibilities: z.array(z.string()),
  required_gates: z.array(AgomGateTypeSchema),
  evidence_requirements: z.array(z.string()),
  sod_rules: z.array(z.string()),
  expected_version_required: z.boolean(),
  idempotency_required: z.boolean(),
  time_aware: z.boolean(),
  side_effects: z.array(z.string()),
  resulting_projection: z.record(z.string()),
  audit_event: z.string().min(1),
  policy_version: z.string().min(1),
}).strict()

export const AgomContractRegistrySchema = z.object({
  contract_version: AgomContractVersionSchema,
  policy_version: z.string().min(1),
  action_count: z.number().int().nonnegative(),
  entity_types: z.array(z.string()),
  gate_types: z.array(AgomGateTypeSchema),
  actor_layers: z.array(AgomActorLayerSchema),
  actions: z.array(AgomActionContractSchema),
}).strict().superRefine((registry, ctx) => {
  if (registry.action_count !== registry.actions.length) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['action_count'],
      message: 'action_count must equal actions.length',
    })
  }
  const actionIds = registry.actions.map((action) => action.action_id)
  if (new Set(actionIds).size !== actionIds.length) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['actions'],
      message: 'action_id values must be unique',
    })
  }
})

export const AgomCapabilityItemSchema = z.object({
  action_id: z.string().min(1),
  mode: AgomActionModeSchema,
  intent: z.string().min(1),
  evaluated_actor_layer: AgomActorLayerSchema.nullable(),
  reason_code: z.string(),
  reason: z.string(),
  missing_requirements: z.array(z.string()),
  gate_results: z.array(AgomGateResultSchema),
}).strict()

export const AgomAuthoritativeCapabilityManifestSchema = z.object({
  contract_version: AgomContractVersionSchema,
  evaluation_policy_version: z.string().min(1),
  entity: AgomEntityRefSchema,
  projection: AgomProjectionSnapshotSchema,
  actor_role: z.string(),
  actor_responsibilities: z.array(z.string()),
  capabilities: z.array(AgomCapabilityItemSchema),
  generated_at: z.string().min(1),
}).strict().superRefine((manifest, ctx) => {
  const actionIds = manifest.capabilities.map((capability) => capability.action_id)
  if (new Set(actionIds).size !== actionIds.length) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['capabilities'],
      message: 'capability action_id values must be unique',
    })
  }
})

export const AgomDecisionPacketSchema = z.object({
  contract_version: AgomContractVersionSchema,
  entity: AgomEntityRefSchema,
  current_projection: AgomProjectionSnapshotSchema,
  requested_action: z.string().min(1),
  risk_context: z.record(z.unknown()),
  evidence_summary: z.record(z.unknown()),
  gate_results: z.array(AgomGateResultSchema),
  sod_eligible: z.boolean(),
  deadline: z.string().nullable(),
  downstream_effects: z.array(z.string()),
}).strict()

export const AgomActionAuditSchema = z.object({
  audit_id: z.string().min(1),
  chain_index: z.number().int().nonnegative(),
  entry_hash: z.string().min(1),
}).strict()

export const AgomActionExecutionSchema = z.object({
  execution_id: z.string().min(1),
  action_id: z.string().min(1),
  organization_id: z.string().min(1),
  project_id: z.string().min(1),
  actor_id: z.string().min(1),
  request_id: z.string().nullable(),
  entity_type: z.string().min(1),
  entity_id: z.string().min(1),
  expected_version: z.number().int().positive(),
  idempotency_key: z.string().min(1),
  request_fingerprint: z.string().min(1),
  contract_version: z.string().min(1),
  contract_policy_version: z.string().min(1),
  evaluation_policy_version: z.string().min(1),
  policy_fingerprint: z.string().min(1),
  correlation_id: z.string().min(1),
  before_projection: AgomProjectionSnapshotSchema,
  gate_results: z.array(AgomGateResultSchema),
  result: z.record(z.unknown()),
  after_projection: AgomProjectionSnapshotSchema,
  audit: AgomActionAuditSchema,
  execution_fingerprint: z.string().min(1),
  replayed: z.boolean(),
  created_at: z.string().min(1),
}).strict()

export const AgomActionRequestSchema = z.object({
  request_id: z.string().min(1),
  organization_id: z.string().min(1),
  project_id: z.string().min(1),
  requested_by_id: z.string().min(1),
  action_id: z.string().min(1),
  entity_type: z.string().min(1),
  entity_id: z.string().min(1),
  expected_version: z.number().int().positive(),
  idempotency_key: z.string().min(1),
  request_fingerprint: z.string().min(1),
  contract_version: z.string().min(1),
  contract_policy_version: z.string().min(1),
  contract_fingerprint: z.string().min(1),
  correlation_id: z.string().min(1),
  parameters: z.record(z.unknown()),
  replayed: z.boolean(),
  created_at: z.string().min(1),
}).strict()

export const AgomWorkSourceTypeSchema = z.enum([
  'governed_action_request',
  'decision_action',
  'assurance_obligation',
  'investigation_case',
  'detection_delivery',
])

export const AgomWorkClaimSchema = z.object({
  version: z.number().int().nonnegative(),
  state: z.enum(['unclaimed', 'claimed', 'expired']),
  claimed_by_id: z.string().nullable(),
  claimed_at: z.string().nullable(),
  lease_expires_at: z.string().nullable(),
  mine: z.boolean(),
}).strict()

export const AgomWorkItemSchema = z.object({
  source_type: AgomWorkSourceTypeSchema,
  source_id: z.string().min(1),
  title: z.string().min(1),
  work_category: z.string().min(1),
  authoritative_state: z.string().min(1),
  source_version: z.number().int().nonnegative(),
  priority_score: z.number().int().min(0).max(100),
  due_at: z.string().nullable(),
  overdue: z.boolean(),
  created_at: z.string().min(1),
  updated_at: z.string().min(1),
  details: z.record(z.unknown()),
  item_key: z.string().min(1),
  organization_id: z.string().min(1),
  project_id: z.string().min(1),
  claim: AgomWorkClaimSchema,
}).strict()

export const AgomWorkQueueSchema = z.object({
  policy_version: z.literal('agom.work-queue.v1'),
  items: z.array(AgomWorkItemSchema),
  total: z.number().int().nonnegative(),
  returned: z.number().int().nonnegative(),
  counts: z.record(z.number().int().nonnegative()),
}).strict().superRefine((queue, ctx) => {
  if (queue.returned !== queue.items.length) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['returned'],
      message: 'returned must equal items.length',
    })
  }
  if (queue.returned > queue.total) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['returned'],
      message: 'returned cannot exceed total',
    })
  }
})

export const AgomWorkOperationSchema = z.enum(['claim', 'renew', 'release'])

export const AgomWorkMutationSchema = z.object({
  policy_version: z.literal('agom.work-queue.v1'),
  source_type: AgomWorkSourceTypeSchema,
  source_id: z.string().min(1),
  project_id: z.string().min(1),
  organization_id: z.string().min(1),
  operation: AgomWorkOperationSchema,
  claim: AgomWorkClaimSchema,
  source_snapshot: z.record(z.unknown()),
  source_snapshot_sha256: z.string().length(64),
  replayed: z.boolean(),
}).strict()


export const AgomExecuteActionInputSchema = z.object({
  action_id: z.string().min(1).max(128),
  project_id: z.string().min(1),
  entity_type: z.string().min(1).max(80),
  entity_id: z.string().min(1).max(128),
  expected_version: z.number().int().positive(),
  idempotency_key: z.string().min(1).max(128),
  request_id: z.string().uuid().optional(),
  correlation_id: z.string().uuid().optional(),
  parameters: z.record(z.unknown()).default({}),
}).strict()

export const AgomActionRequestCreateInputSchema = AgomExecuteActionInputSchema.omit({
  request_id: true,
}).strict()

export const AgomClaimStateSchema = z.enum(['unclaimed', 'claimed', 'expired', 'mine'])

export const AgomWorkQueueQuerySchema = z.object({
  project_id: z.string().uuid().optional(),
  source_type: AgomWorkSourceTypeSchema.optional(),
  claim_state: AgomClaimStateSchema.optional(),
  limit: z.number().int().min(1).max(500).optional(),
}).strict()

export const AgomWorkClaimMutationInputSchema = z.object({
  project_id: z.string().uuid(),
  expected_claim_version: z.number().int().nonnegative(),
  idempotency_key: z.string().min(8).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/),
  lease_seconds: z.number().int().min(60).max(86400).optional(),
}).strict()

export const AgomResponsibilityAssignmentSchema = z.object({
  assignment_id: z.string().min(1),
  organization_id: z.string().min(1),
  project_id: z.string().nullable(),
  membership_id: z.string().min(1),
  responsibility: z.string().min(1),
  scope_kind: z.string().min(1),
  entity_type: z.string(),
  entity_id: z.string(),
  valid_from: z.string().min(1),
  valid_until: z.string().nullable(),
  policy_version: z.string().min(1),
  request_fingerprint: z.string().min(1),
  grant_fingerprint: z.string().min(1),
  issued_by: z.string().min(1),
  issued_at: z.string().min(1),
  supersedes_assignment_id: z.string().nullable(),
  replayed: z.boolean(),
}).strict()

export const AgomResponsibilityRevocationSchema = z.object({
  revocation_id: z.string().min(1),
  assignment_id: z.string().min(1),
  policy_version: z.string().min(1),
  request_fingerprint: z.string().min(1),
  revocation_fingerprint: z.string().min(1),
  revoked_by: z.string().min(1),
  revoked_at: z.string().min(1),
  replayed: z.boolean(),
}).strict()

export const AgomActorAuthoritySchema = z.object({
  organization_id: z.string().min(1),
  project_id: z.string().nullable(),
  membership_id: z.string().min(1),
  role: z.string().min(1),
  responsibilities: z.array(z.string()),
}).strict()

export const AgomResponsibilityChainSchema = z.object({
  valid: z.boolean(),
  entries: z.number().int().nonnegative(),
  head: z.string(),
  broken_at: z.number().int().nullable(),
  reason: z.string(),
}).strict()

export const AgomResponsibilityGrantInputSchema = z.object({
  organization_id: z.string().min(1),
  membership_id: z.string().min(1),
  responsibility: z.string().min(1).max(64),
  scope_kind: z.string().min(1).max(24),
  reason: z.string().min(1),
  idempotency_key: z.string().min(1).max(128),
  project_id: z.string().nullable().optional(),
  entity_type: z.string().max(80).default(''),
  entity_id: z.string().max(128).default(''),
  valid_from: z.string().optional(),
  valid_until: z.string().nullable().optional(),
  supersedes_assignment_id: z.string().nullable().optional(),
}).strict()

export const AgomResponsibilityRevokeInputSchema = z.object({
  reason: z.string().min(1),
  idempotency_key: z.string().min(1).max(128),
}).strict()

export type AgomActionContract = z.infer<typeof AgomActionContractSchema>
export type AgomContractRegistry = z.infer<typeof AgomContractRegistrySchema>
export type AgomAuthoritativeCapabilityManifest = z.infer<typeof AgomAuthoritativeCapabilityManifestSchema>
export type AgomCapabilityItem = z.infer<typeof AgomCapabilityItemSchema>
export type AgomDecisionPacket = z.infer<typeof AgomDecisionPacketSchema>
export type AgomActionExecution = z.infer<typeof AgomActionExecutionSchema>
export type AgomActionRequest = z.infer<typeof AgomActionRequestSchema>
export type AgomWorkQueue = z.infer<typeof AgomWorkQueueSchema>
export type AgomWorkItem = z.infer<typeof AgomWorkItemSchema>
export type AgomWorkMutation = z.infer<typeof AgomWorkMutationSchema>

export type AgomExecuteActionInput = z.infer<typeof AgomExecuteActionInputSchema>
export type AgomActionRequestCreateInput = z.infer<typeof AgomActionRequestCreateInputSchema>
export type AgomWorkSourceType = z.infer<typeof AgomWorkSourceTypeSchema>
export type AgomClaimState = z.infer<typeof AgomClaimStateSchema>
export type AgomWorkQueueQuery = z.infer<typeof AgomWorkQueueQuerySchema>
export type AgomWorkClaimMutationInput = z.infer<typeof AgomWorkClaimMutationInputSchema>
export type AgomResponsibilityAssignment = z.infer<typeof AgomResponsibilityAssignmentSchema>
export type AgomResponsibilityRevocation = z.infer<typeof AgomResponsibilityRevocationSchema>
export type AgomActorAuthority = z.infer<typeof AgomActorAuthoritySchema>
export type AgomResponsibilityChain = z.infer<typeof AgomResponsibilityChainSchema>
export type AgomResponsibilityGrantInput = z.infer<typeof AgomResponsibilityGrantInputSchema>
export type AgomResponsibilityRevokeInput = z.infer<typeof AgomResponsibilityRevokeInputSchema>
