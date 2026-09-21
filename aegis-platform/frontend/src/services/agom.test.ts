import { afterEach, describe, expect, it, vi } from 'vitest'

import { apiHelpers } from '@/services/api'
import { AgomSdkError, agomSdk, buildAgomIdempotencyKey } from '@/services/agom'

vi.mock('@/services/api', () => ({
  apiHelpers: {
    get: vi.fn(),
    post: vi.fn(),
  },
}))

const mockedGet = vi.mocked(apiHelpers.get)
const mockedPost = vi.mocked(apiHelpers.post)

const projection = {
  lifecycle: 'verified',
  outcome: null,
  posture: null,
  governance: null,
  assurance: null,
  version: 7,
}

const execution = {
  execution_id: '11111111-1111-4111-8111-111111111111',
  action_id: 'finding.close',
  organization_id: '22222222-2222-4222-8222-222222222222',
  project_id: '33333333-3333-4333-8333-333333333333',
  actor_id: '44444444-4444-4444-8444-444444444444',
  request_id: null,
  entity_type: 'finding',
  entity_id: '55555555-5555-4555-8555-555555555555',
  expected_version: 7,
  idempotency_key: 'ui-finding-close:55555555:v7',
  request_fingerprint: 'a'.repeat(64),
  contract_version: 'agom.v1',
  contract_policy_version: 'agom-governance.v1',
  evaluation_policy_version: 'agom-evaluation.v1',
  policy_fingerprint: 'b'.repeat(64),
  correlation_id: '66666666-6666-4666-8666-666666666666',
  before_projection: projection,
  gate_results: [],
  result: { status: 'fixed', version: 8 },
  after_projection: { ...projection, lifecycle: 'closed', version: 8 },
  audit: { audit_id: 'audit-1', chain_index: 1, entry_hash: 'c'.repeat(64) },
  execution_fingerprint: 'd'.repeat(64),
  replayed: false,
  created_at: '2026-09-21T00:00:00+00:00',
}

afterEach(() => {
  vi.clearAllMocks()
})

describe('AGOM frontend SDK', () => {
  it('executes governed actions through the canonical API and validates the response', async () => {
    mockedPost.mockResolvedValue(execution)

    const result = await agomSdk.executeAction({
      action_id: 'finding.close',
      project_id: execution.project_id,
      entity_type: 'finding',
      entity_id: execution.entity_id,
      expected_version: 7,
      idempotency_key: execution.idempotency_key,
      parameters: {},
    })

    expect(mockedPost).toHaveBeenCalledWith('/assurance/governance/actions/execute', {
      action_id: 'finding.close',
      project_id: execution.project_id,
      entity_type: 'finding',
      entity_id: execution.entity_id,
      expected_version: 7,
      idempotency_key: execution.idempotency_key,
      parameters: {},
    })
    expect(result.execution_id).toBe(execution.execution_id)
  })

  it('validates work queue mutation response shape instead of treating it as a work item', async () => {
    const mutation = {
      policy_version: 'agom.work-queue.v1',
      source_type: 'governed_action_request',
      source_id: '77777777-7777-4777-8777-777777777777',
      project_id: execution.project_id,
      organization_id: execution.organization_id,
      operation: 'claim',
      claim: {
        version: 1,
        state: 'claimed',
        claimed_by_id: execution.actor_id,
        claimed_at: '2026-09-21T00:00:00+00:00',
        lease_expires_at: '2026-09-21T00:05:00+00:00',
        mine: true,
      },
      source_snapshot: {
        policy_version: 'agom.work-queue.v1',
        source_type: 'governed_action_request',
        source_id: '77777777-7777-4777-8777-777777777777',
      },
      source_snapshot_sha256: 'e'.repeat(64),
      replayed: false,
    }
    mockedPost.mockResolvedValue(mutation)

    const result = await agomSdk.claimWork('governed_action_request', mutation.source_id, {
      project_id: execution.project_id,
      expected_claim_version: 0,
      idempotency_key: 'claim-work-queue-001',
      lease_seconds: 300,
    })

    expect(result.operation).toBe('claim')
    expect(result.claim.mine).toBe(true)
    expect(mockedPost).toHaveBeenCalledWith(
      '/work-queue/governed_action_request/' + mutation.source_id + '/claim',
      expect.objectContaining({ expected_claim_version: 0, lease_seconds: 300 }),
    )
  })

  it('preserves authoritative blocked reason codes and missing requirements', async () => {
    mockedPost.mockRejectedValue({
      response: {
        status: 409,
        data: {
          detail: {
            code: 'GATE_NOT_SATISFIED',
            reason: 'Closure proof is incomplete.',
            missing_requirements: ['closure:fail'],
          },
        },
      },
    })

    await expect(agomSdk.executeAction({
      action_id: 'finding.close',
      project_id: execution.project_id,
      entity_type: 'finding',
      entity_id: execution.entity_id,
      expected_version: 7,
      idempotency_key: execution.idempotency_key,
      parameters: {},
    })).rejects.toMatchObject({
      name: 'AgomSdkError',
      code: 'GATE_NOT_SATISFIED',
      status: 409,
      missingRequirements: ['closure:fail'],
    })
  })

  it('fails closed when a backend response drifts from the AGOM contract', async () => {
    mockedPost.mockResolvedValue({ execution_id: 'broken-only' })

    await expect(agomSdk.executeAction({
      action_id: 'finding.close',
      project_id: execution.project_id,
      entity_type: 'finding',
      entity_id: execution.entity_id,
      expected_version: 7,
      idempotency_key: execution.idempotency_key,
      parameters: {},
    })).rejects.toMatchObject({ code: 'AGOM_CONTRACT_MISMATCH' })
  })

  it('builds stable safe idempotency keys and rejects ambiguous short keys', () => {
    expect(buildAgomIdempotencyKey('finding.close', 'finding-1', 7)).toBe('finding.close:finding-1:7')
    expect(() => buildAgomIdempotencyKey('x')).toThrow(AgomSdkError)
  })

  it('reads authoritative capabilities with project scope encoded by the SDK', async () => {
    mockedGet.mockResolvedValue({
      contract_version: 'agom.v1',
      evaluation_policy_version: 'agom-capability.v1',
      entity: {
        entity_type: 'finding',
        entity_id: execution.entity_id,
        tenant_id: execution.organization_id,
        project_id: execution.project_id,
      },
      projection,
      actor_role: 'owner',
      actor_responsibilities: ['closure_approver'],
      capabilities: [{
        action_id: 'finding.close',
        mode: 'enabled',
        intent: 'Close a verified finding',
        evaluated_actor_layer: 'govern',
        reason_code: '',
        reason: '',
        missing_requirements: [],
        gate_results: [],
      }],
      generated_at: '2026-09-21T00:00:00+00:00',
    })

    const result = await agomSdk.getCapabilities({
      projectId: execution.project_id,
      entityType: 'finding',
      entityId: execution.entity_id,
    })

    expect(result.capabilities[0].mode).toBe('enabled')
    expect(mockedGet).toHaveBeenCalledWith(
      '/assurance/governance/capabilities/finding/' + execution.entity_id + '?project_id=' + execution.project_id,
    )
  })
})
