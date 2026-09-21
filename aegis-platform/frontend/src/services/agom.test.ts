import { beforeEach, describe, expect, it, vi } from 'vitest'

import { apiHelpers } from '@/services/api'
import { agomApi } from './agom'

vi.mock('@/services/api', () => ({
  apiHelpers: {
    get: vi.fn(),
    post: vi.fn(),
  },
}))

const mockedGet = vi.mocked(apiHelpers.get)
const mockedPost = vi.mocked(apiHelpers.post)

const registry = {
  contract_version: 'agom.v1',
  policy_version: 'agom-governance.v1',
  action_count: 0,
  entity_types: [],
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
  actions: [],
}

describe('agomApi', () => {
  beforeEach(() => {
    vi.resetAllMocks()
  })

  it('parses contract registry responses', async () => {
    mockedGet.mockResolvedValueOnce(registry)
    await expect(agomApi.contracts()).resolves.toEqual(registry)
    expect(mockedGet).toHaveBeenCalledWith('/assurance/governance/contracts', undefined)
  })

  it('encodes capability path identity and sends project scope separately', async () => {
    mockedGet.mockResolvedValueOnce({
      contract_version: 'agom.v1',
      evaluation_policy_version: 'agom-entity-capability.v1',
      entity: {
        entity_type: 'finding',
        entity_id: 'finding/1',
        tenant_id: 'org-1',
        project_id: 'project-1',
      },
      projection: {
        lifecycle: 'confirmed',
        outcome: null,
        posture: null,
        governance: null,
        assurance: null,
        version: 2,
      },
      actor_role: 'analyst',
      actor_responsibilities: [],
      capabilities: [],
      generated_at: '2026-09-21T00:00:00Z',
    })

    await agomApi.capabilities({
      projectId: 'project-1',
      entityType: 'finding',
      entityId: 'finding/1',
    })

    expect(mockedGet).toHaveBeenCalledWith(
      '/assurance/governance/capabilities/finding/finding%2F1',
      { params: { project_id: 'project-1' } },
    )
  })

  it('rejects forged authority before sending action requests', async () => {
    await expect(agomApi.createActionRequest({
      action_id: 'finding.close',
      project_id: 'project-1',
      entity_type: 'finding',
      entity_id: 'finding-1',
      expected_version: 3,
      idempotency_key: 'request-finding-close-v3',
      parameters: {},
      actor_role: 'owner',
    } as never)).rejects.toThrow()

    expect(mockedPost).not.toHaveBeenCalled()
  })

  it('validates work mutation evidence returned by the server', async () => {
    mockedPost.mockResolvedValueOnce({
      policy_version: 'agom.work-queue.v1',
      source_type: 'governed_action_request',
      source_id: '11111111-1111-1111-1111-111111111111',
      project_id: '22222222-2222-2222-2222-222222222222',
      organization_id: '33333333-3333-3333-3333-333333333333',
      operation: 'claim',
      claim: {
        version: 1,
        state: 'claimed',
        claimed_by_id: 'user-1',
        claimed_at: '2026-09-21T00:00:00Z',
        lease_expires_at: '2026-09-21T00:10:00Z',
        mine: true,
      },
      source_snapshot: {
        policy_version: 'agom.work-queue.v1',
        source_type: 'governed_action_request',
        source_id: '11111111-1111-1111-1111-111111111111',
        authoritative_state: 'pending_approval',
        source_version: 3,
        title: 'Governed approval: finding.close',
        priority_score: 75,
        details: {},
        captured_at: '2026-09-21T00:00:00Z',
      },
      source_snapshot_sha256: 'b'.repeat(64),
      replayed: false,
    })

    const result = await agomApi.claimWork(
      'governed_action_request',
      '11111111-1111-1111-1111-111111111111',
      {
        project_id: '22222222-2222-2222-2222-222222222222',
        expected_claim_version: 0,
        idempotency_key: 'claim-request-0001',
        lease_seconds: 600,
      },
    )

    expect(result.claim.version).toBe(1)
    expect(mockedPost).toHaveBeenCalledWith(
      '/work-queue/governed_action_request/11111111-1111-1111-1111-111111111111/claim',
      {
        project_id: '22222222-2222-2222-2222-222222222222',
        expected_claim_version: 0,
        idempotency_key: 'claim-request-0001',
        lease_seconds: 600,
      },
      undefined,
    )
  })
})
