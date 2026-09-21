import { describe, expect, it } from 'vitest'

import {
  AgomActionRequestInputSchema,
  AgomAuthoritativeCapabilityManifestSchema,
  AgomContractRegistrySchema,
  AgomWorkMutationSchema,
  AgomWorkQueueSchema,
} from './agom'

const projection = {
  lifecycle: 'verified',
  outcome: null,
  posture: null,
  governance: null,
  assurance: null,
  version: 4,
}

const gate = {
  gate: 'closure',
  state: 'pass',
  reason_code: '',
  reason: '',
  missing_requirements: [],
  evidence_refs: ['evidence-1'],
  policy_version: 'agom-governance.v1',
  evaluated_at: '2026-09-21T00:00:00Z',
}

const action = {
  action_id: 'finding.close',
  entity_type: 'finding',
  intent: 'Close a verified finding',
  allowed_states: ['verified'],
  actor_layers: ['govern'],
  allowed_roles: ['manager', 'admin', 'owner'],
  required_responsibilities: ['closure_approver'],
  required_gates: ['closure', 'independent_verification'],
  evidence_requirements: ['remediation_verification', 'closure_proof'],
  sod_rules: ['actor_must_not_be_remediation_verifier'],
  expected_version_required: true,
  idempotency_required: true,
  time_aware: false,
  side_effects: [],
  resulting_projection: { lifecycle: 'closed' },
  audit_event: 'finding.closed',
  policy_version: 'agom-governance.v1',
}

describe('AGOM authoritative contracts', () => {
  it('accepts a coherent contract registry and rejects action count drift', () => {
    const registry = {
      contract_version: 'agom.v1',
      policy_version: 'agom-governance.v1',
      action_count: 1,
      entity_types: ['finding'],
      gate_types: [
        'authorization',
        'evidence',
        'validation',
        'publication',
        'closure',
        'expiry_review',
        'live_acceptance',
        'independent_verification',
      ],
      actor_layers: ['operate', 'govern', 'assure'],
      actions: [action],
    }
    expect(AgomContractRegistrySchema.parse(registry).actions[0].action_id).toBe('finding.close')
    expect(() => AgomContractRegistrySchema.parse({ ...registry, action_count: 2 })).toThrow()
  })

  it('rejects client-invented authority on an action request', () => {
    expect(() => AgomActionRequestInputSchema.parse({
      action_id: 'finding.close',
      project_id: 'project-1',
      entity_type: 'finding',
      entity_id: 'finding-1',
      expected_version: 4,
      idempotency_key: 'ui-finding-close-v4',
      parameters: {},
      actor_role: 'owner',
      actor_responsibilities: ['closure_approver'],
    })).toThrow()
  })

  it('validates server-authoritative capability modes rather than deriving eligibility', () => {
    const manifest = {
      contract_version: 'agom.v1',
      evaluation_policy_version: 'agom-entity-capability.v1',
      entity: {
        entity_type: 'finding',
        entity_id: 'finding-1',
        tenant_id: 'org-1',
        project_id: 'project-1',
      },
      projection,
      actor_role: 'manager',
      actor_responsibilities: ['closure_approver'],
      capabilities: [{
        action_id: 'finding.close',
        mode: 'blocked',
        intent: 'Close a verified finding',
        evaluated_actor_layer: 'govern',
        reason_code: 'INDEPENDENT_VERIFICATION_REQUIRED',
        reason: 'Independent verification is required.',
        missing_requirements: ['independent_verification'],
        gate_results: [gate],
      }],
      generated_at: '2026-09-21T00:00:00Z',
    }
    expect(AgomAuthoritativeCapabilityManifestSchema.parse(manifest).capabilities[0].mode).toBe('blocked')
    expect(() => AgomAuthoritativeCapabilityManifestSchema.parse({
      ...manifest,
      capabilities: [{ ...manifest.capabilities[0], mode: 'client_allowed' }],
    })).toThrow()
  })

  it('distinguishes work queue listing from mutation evidence', () => {
    const claim = {
      version: 1,
      state: 'claimed',
      claimed_by_id: 'user-1',
      claimed_at: '2026-09-21T00:00:00Z',
      lease_expires_at: '2026-09-21T00:10:00Z',
      mine: true,
    }
    const queue = {
      policy_version: 'agom.work-queue.v1',
      items: [{
        source_type: 'governed_action_request',
        source_id: '11111111-1111-1111-1111-111111111111',
        title: 'Governed approval: finding.close',
        work_category: 'approval',
        authoritative_state: 'pending_approval',
        source_version: 4,
        priority_score: 75,
        due_at: null,
        overdue: false,
        created_at: '2026-09-21T00:00:00Z',
        updated_at: '2026-09-21T00:00:00Z',
        details: {},
        item_key: 'governed_action_request:11111111-1111-1111-1111-111111111111',
        organization_id: 'org-1',
        project_id: 'project-1',
        claim,
      }],
      total: 1,
      returned: 1,
      counts: { approval: 1 },
    }
    expect(AgomWorkQueueSchema.parse(queue).returned).toBe(1)

    const mutation = {
      policy_version: 'agom.work-queue.v1',
      source_type: 'governed_action_request',
      source_id: '11111111-1111-1111-1111-111111111111',
      project_id: 'project-1',
      organization_id: 'org-1',
      operation: 'claim',
      claim,
      source_snapshot: {
        policy_version: 'agom.work-queue.v1',
        source_type: 'governed_action_request',
        source_id: '11111111-1111-1111-1111-111111111111',
        authoritative_state: 'pending_approval',
        source_version: 4,
        title: 'Governed approval: finding.close',
        priority_score: 75,
        details: {},
        captured_at: '2026-09-21T00:00:00Z',
      },
      source_snapshot_sha256: 'a'.repeat(64),
      replayed: false,
    }
    expect(AgomWorkMutationSchema.parse(mutation).operation).toBe('claim')
    expect(() => AgomWorkMutationSchema.parse({ ...queue.items[0], replayed: false })).toThrow()
  })
})
