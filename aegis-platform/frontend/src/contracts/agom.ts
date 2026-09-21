import { z } from 'zod'

const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/)
const NonEmptyStringSchema = z.string().min(1)
const OptionalNullableStringSchema = z.string().nullable().optional()

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
export const AgomWorkSourceTypeSchema = z.enum([
  'governed_action_request',
  'decision_action',
  'assurance_obligation',
  'investigation_case',
  'detection_delivery',
])
export const AgomWorkClaimStateSchema = z.enum(['unclaimed', 'claimed', 'expired'])
export const AgomWorkOperationSchema = z.enum(['claim', 'renew', 'release'])

export const AgomEntityRefSchema = z.object({
  entity_type: NonEmptyStringSchema,
  entity_id: NonEmptyStringSchema,
  tenant_id: OptionalNullableStringSchema,
  project_id: OptionalNullableStringSchema,
}).strict()

export const AgomProjectionSnapshotSchema = z.object({
  lifecycle: OptionalNullableStringSchema,
  outcome: OptionalNullableStringSchema,
  posture: OptionalNullableStringSchema,
  governance: OptionalNullableStringSchema,
  assurance: OptionalNullableStringSchema,
  version: z.number().int().nonnegative().nullable().optional(),
}).strict()

export const AgomGateResultSchema = z.object({
  gate: AgomGateTypeSchema,
  state: AgomGateStateSchema,
  reason_code: z.string(),
  reason: z.string(),
  missing_requirements: z.array(z.string()),
  evidence_refs: z.array(z.string()),
  policy_version: z.string(),
  evaluated_at: OptionalNullableStringSchema,
}).strict()

export const AgomActionContractSchema = z.object({
  action_id: NonEmptyStringSchema,
  entity_type: NonEmptyStringSchema,
  intent: NonEmptyStringSchema,
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
  audit_event: NonEmptyStringSchema,
  policy_version: NonEmptyStringSchema,
}).strict()

export const AgomContractRegistrySchema = z.object({
  contract_version: AgomContractVersionSchema,
  policy_version: NonEmptyStringSchema,
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
  action_id: NonEmptyStringSchema,
  mode: AgomActionModeSchema,
  intent: NonEmptyStringSchema,
  evaluated_actor_layer: AgomActorLayerSchema.nullable().optional(),
  reason_code: z.string(),
  reason: z.string(),
  missing_requirements: z.array(z.string()),
  gate_results: z.array(AgomGateResultSchema),
}).strict()

export const AgomAuthoritativeCapabilityManifestSchema = z.object({
  contract_version: AgomContractVersionSchema,
  evaluation_policy_version: NonEmptyStringSchema,
  entity: AgomEntityRefSchema,
  projection: AgomProjectionSnapshotSchema,
  actor_role: z.string(),
  actor_responsibilities: z.array(z.string()),
  capabilities: z.array(AgomCapabilityItemSchema),
  generated_at: NonEmptyStringSchema,
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
  requested_action: NonEmptyStringSchema,
  risk_context: z.record(z.unknown()),
  evidence_summary: z.record(z.unknown()),
  gate_results: z.array(AgomGateResultSchema),
  sod_eligible: z.boolean(),
  deadline: z.string().nullable(),
  downstream_effects: z.array(z.string()),
}).strict()

export const AgomActionRequestInputSchema = z.object({
  action_id: z.string().min(1).max(128),
  project_id: NonEmptyStringSchema,
  entity_type: z.string().min(1).max(80),
  entity_id: z.string().min(1).max(128),
  expected_version: z.number().int().positive(),
  idempotency_key: z.string().min(1).max(128),
  correlation_id: z.string().uuid().nullable().optional(),
  parameters: z.record(z.unknown()).default({}),
}).strict()

export const AgomActionExecutionInputSchema = AgomActionRequestInputSchema.extend({
  request_id: z.string().uuid().nullable().optional(),
}).strict()

export const AgomActionAuditSchema = z.object({
  audit_id: NonEmptyStringSchema,
  chain_index: z.number().int().nonnegative(),
  entry_hash: Sha256Schema,
}).strict()

export const AgomActionExecutionSchema = z.object({
  execution_id: NonEmptyStringSchema,
  action_id: NonEmptyStringSchema,
  organization_id: NonEmptyStringSchema,
  project_id: NonEmptyStringSchema,
  actor_id: NonEmptyStringSchema,
  request_id: z.string().nullable().optional(),
  entity_type: NonEmptyStringSchema,
  entity_id: NonEmptyStringSchema,
  expected_version: z.number().int().positive(),
  idempotency_key: NonEmptyStringSchema,
  request_fingerprint: Sha256Schema,
  contract_version: AgomContractVersionSchema,
  contract_policy_version: NonEmptyStringSchema,
  evaluation_policy_version: NonEmptyStringSchema,
  policy_fingerprint: Sha256Schema,
  correlation_id: z.string().uuid(),
  before_projection: AgomProjectionSnapshotSchema,
  gate_results: z.array(AgomGateResultSchema),
  result: z.record(z.unknown()),
  after_projection: AgomProjectionSnapshotSchema,
  audit: AgomActionAuditSchema,
  execution_fingerprint: Sha256Schema,
  replayed: z.boolean(),
  created_at: NonEmptyStringSchema,
}).strict()

export const AgomActionRequestSchema = z.object({
  request_id: NonEmptyStringSchema,
  organization_id: NonEmptyStringSchema,
  project_id: NonEmptyStringSchema,
  requested_by_id: NonEmptyStringSchema,
  action_id: NonEmptyStringSchema,
  entity_type: NonEmptyStringSchema,
  entity_id: NonEmptyStringSchema,
  expected_version: z.number().int().positive(),
  idempotency_key: NonEmptyStringSchema,
  request_fingerprint: Sha256Schema,
  contract_version: AgomContractVersionSchema,
  contract_policy_version: NonEmptyStringSchema,
  contract_fingerprint: Sha256Schema,
  correlation_id: z.string().uuid(),
  parameters: z.record(z.unknown()),
  replayed: z.boolean(),
  created_at: NonEmptyStringSchema,
}).strict()

export const AgomActorAuthoritySchema = z.object({
  organization_id: NonEmptyStringSchema,
  project_id: z.string().nullable(),
  membership_id: NonEmptyStringSchema,
  role: NonEmptyStringSchema,
  responsibilities: z.array(z.string()),
}).strict()

export const AgomResponsibilityGrantInputSchema = z.object({
  organization_id: NonEmptyStringSchema,
  membership_id: NonEmptyStringSchema,
  responsibility: z.string().min(1).max(64),
  scope_kind: z.string().min(1).max(24),
  reason: NonEmptyStringSchema,
  idempotency_key: z.string().min(1).max(128),
  project_id: z.string().nullable().optional(),
  entity_type: z.string().max(80).default(''),
  entity_id: z.string().max(128).default(''),
  valid_from: z.string().nullable().optional(),
  valid_until: z.string().nullable().optional(),
  supersedes_assignment_id: z.string().nullable().optional(),
}).strict()

export const AgomResponsibilityAssignmentSchema = z.object({
  assignment_id: NonEmptyStringSchema,
  organization_id: NonEmptyStringSchema,
  project_id: z.string().nullable(),
  membership_id: NonEmptyStringSchema,
  responsibility: NonEmptyStringSchema,
  scope_kind: NonEmptyStringSchema,
  entity_type: z.string(),
  entity_id: z.string(),
  valid_from: NonEmptyStringSchema,
  valid_until: z.string().nullable(),
  policy_version: NonEmptyStringSchema,
  request_fingerprint: Sha256Schema,
  grant_fingerprint: Sha256Schema,
  issued_by: NonEmptyStringSchema,
  issued_at: NonEmptyStringSchema,
  supersedes_assignment_id: z.string().nullable(),
  replayed: z.boolean(),
}).strict()

export const AgomResponsibilityRevokeInputSchema = z.object({
  reason: NonEmptyStringSchema,
  idempotency_key: z.string().min(1).max(128),
}).strict()

export const AgomResponsibilityRevocationSchema = z.object({
  revocation_id: NonEmptyStringSchema,
  assignment_id: NonEmptyStringSchema,
  policy_version: NonEmptyStringSchema,
  request_fingerprint: Sha256Schema,
  revocation_fingerprint: Sha256Schema,
  revoked_by: NonEmptyStringSchema,
  revoked_at: NonEmptyStringSchema,
  replayed: z.boolean(),
}).strict()

export const AgomResponsibilityChainSchema = z.object({
  valid: z.boolean(),
  entries: z.number().int().nonnegative(),
  head: z.string(),
  broken_at: z.number().int().nonnegative().nullable(),
  reason: z.string(),
}).strict()

export const AgomWorkClaimSchema = z.object({
  version: z.number().int().nonnegative(),
  state: AgomWorkClaimStateSchema,
  claimed_by_id: z.string().nullable(),
  claimed_at: z.string().nullable(),
  lease_expires_at: z.string().nullable(),
  mine: z.boolean(),
}).strict()

export const AgomWorkItemSchema = z.object({
  source_type: AgomWorkSourceTypeSchema,
  source_id: NonEmptyStringSchema,
  title: NonEmptyStringSchema,
  work_category: NonEmptyStringSchema,
  authoritative_state: NonEmptyStringSchema,
  source_version: z.number().int().nonnegative(),
  priority_score: z.number().int().min(0).max(100),
  due_at: z.string().nullable(),
  overdue: z.boolean(),
  created_at: NonEmptyStringSchema,
  updated_at: NonEmptyStringSchema,
  details: z.record(z.unknown()),
  item_key: NonEmptyStringSchema,
  organization_id: NonEmptyStringSchema,
  project_id: NonEmptyStringSchema,
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

const WorkIdempotencyKeySchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/)

export const AgomWorkLeaseMutationInputSchema = z.object({
  project_id: z.string().uuid(),
  expected_claim_version: z.number().int().nonnegative(),
  idempotency_key: WorkIdempotencyKeySchema,
  lease_seconds: z.number().int().min(60).max(86400),
}).strict()

export const AgomWorkReleaseMutationInputSchema = z.object({
  project_id: z.string().uuid(),
  expected_claim_version: z.number().int().nonnegative(),
  idempotency_key: WorkIdempotencyKeySchema,
}).strict()

export const AgomWorkSourceSnapshotSchema = z.object({
  policy_version: z.literal('agom.work-queue.v1'),
  source_type: AgomWorkSourceTypeSchema,
  source_id: NonEmptyStringSchema,
  authoritative_state: NonEmptyStringSchema,
  source_version: z.number().int().nonnegative(),
  title: NonEmptyStringSchema,
  priority_score: z.number().int().min(0).max(100),
  details: z.record(z.unknown()),
  captured_at: NonEmptyStringSchema,
}).strict()

export const AgomWorkMutationSchema = z.object({
  policy_version: z.literal('agom.work-queue.v1'),
  source_type: AgomWorkSourceTypeSchema,
  source_id: NonEmptyStringSchema,
  project_id: NonEmptyStringSchema,
  organization_id: NonEmptyStringSchema,
  operation: AgomWorkOperationSchema,
  claim: AgomWorkClaimSchema,
  source_snapshot: AgomWorkSourceSnapshotSchema,
  source_snapshot_sha256: Sha256Schema,
  replayed: z.boolean(),
}).strict()

export type AgomActionContract = z.infer<typeof AgomActionContractSchema>
export type AgomContractRegistry = z.infer<typeof AgomContractRegistrySchema>
export type AgomAuthoritativeCapabilityManifest = z.infer<typeof AgomAuthoritativeCapabilityManifestSchema>
export type AgomCapabilityItem = z.infer<typeof AgomCapabilityItemSchema>
export type AgomDecisionPacket = z.infer<typeof AgomDecisionPacketSchema>
export type AgomActionRequestInput = z.input<typeof AgomActionRequestInputSchema>
export type AgomActionExecutionInput = z.input<typeof AgomActionExecutionInputSchema>
export type AgomActionExecution = z.infer<typeof AgomActionExecutionSchema>
export type AgomActionRequest = z.infer<typeof AgomActionRequestSchema>
export type AgomActorAuthority = z.infer<typeof AgomActorAuthoritySchema>
export type AgomResponsibilityGrantInput = z.input<typeof AgomResponsibilityGrantInputSchema>
export type AgomResponsibilityAssignment = z.infer<typeof AgomResponsibilityAssignmentSchema>
export type AgomResponsibilityRevokeInput = z.input<typeof AgomResponsibilityRevokeInputSchema>
export type AgomResponsibilityRevocation = z.infer<typeof AgomResponsibilityRevocationSchema>
export type AgomResponsibilityChain = z.infer<typeof AgomResponsibilityChainSchema>
export type AgomWorkSourceType = z.infer<typeof AgomWorkSourceTypeSchema>
export type AgomWorkClaimState = z.infer<typeof AgomWorkClaimStateSchema>
export type AgomWorkQueue = z.infer<typeof AgomWorkQueueSchema>
export type AgomWorkItem = z.infer<typeof AgomWorkItemSchema>
export type AgomWorkLeaseMutationInput = z.input<typeof AgomWorkLeaseMutationInputSchema>
export type AgomWorkReleaseMutationInput = z.input<typeof AgomWorkReleaseMutationInputSchema>
export type AgomWorkMutation = z.infer<typeof AgomWorkMutationSchema>
