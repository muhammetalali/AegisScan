// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { WorkflowControlTowerPage } from './WorkflowControlTowerPage'
import { apiHelpers } from '@/services/api'
import { agomSdk, buildAgomIdempotencyKey } from '@/services/agom'

vi.mock('@/services/api', () => ({
  apiHelpers: {
    get: vi.fn(),
  },
}))

vi.mock('@/services/agom', () => ({
  agomSdk: {
    listWorkQueue: vi.fn(),
    claimWork: vi.fn(),
    renewWork: vi.fn(),
    releaseWork: vi.fn(),
  },
  buildAgomIdempotencyKey: vi.fn(() => 'ops:claim:key-0001'),
  getAgomErrorMessage: (error: unknown, fallback: string) => error instanceof Error ? error.message : fallback,
}))

const mockedGet = vi.mocked(apiHelpers.get)
const mockedList = vi.mocked(agomSdk.listWorkQueue)
const mockedClaim = vi.mocked(agomSdk.claimWork)
const mockedRenew = vi.mocked(agomSdk.renewWork)
const mockedRelease = vi.mocked(agomSdk.releaseWork)
const mockedKey = vi.mocked(buildAgomIdempotencyKey)

const projectId = '33333333-3333-4333-8333-333333333333'

const queue = {
  policy_version: 'agom.work-queue.v1' as const,
  total: 2,
  returned: 2,
  counts: { approval: 1, assurance: 1 },
  items: [
    {
      source_type: 'governed_action_request' as const,
      source_id: '77777777-7777-4777-8777-777777777777',
      title: 'Governed approval: finding.disposition.accept_risk',
      work_category: 'approval',
      authoritative_state: 'pending_approval',
      source_version: 7,
      priority_score: 95,
      due_at: null,
      overdue: false,
      created_at: '2026-09-21T00:00:00+00:00',
      updated_at: '2026-09-21T00:00:00+00:00',
      details: { action_id: 'finding.disposition.accept_risk' },
      item_key: 'governed_action_request:77777777-7777-4777-8777-777777777777',
      organization_id: '22222222-2222-4222-8222-222222222222',
      project_id: projectId,
      claim: {
        version: 0,
        state: 'unclaimed' as const,
        claimed_by_id: null,
        claimed_at: null,
        lease_expires_at: null,
        mine: false,
      },
    },
    {
      source_type: 'assurance_obligation' as const,
      source_id: '88888888-8888-4888-8888-888888888888',
      title: 'Assurance review: recurrence',
      work_category: 'assurance',
      authoritative_state: 'due',
      source_version: 3,
      priority_score: 90,
      due_at: '2026-09-21T01:00:00+00:00',
      overdue: true,
      created_at: '2026-09-20T00:00:00+00:00',
      updated_at: '2026-09-21T00:00:00+00:00',
      details: { kind: 'recurrence' },
      item_key: 'assurance_obligation:88888888-8888-4888-8888-888888888888',
      organization_id: '22222222-2222-4222-8222-222222222222',
      project_id: projectId,
      claim: {
        version: 4,
        state: 'claimed' as const,
        claimed_by_id: '44444444-4444-4444-8444-444444444444',
        claimed_at: '2026-09-21T00:10:00+00:00',
        lease_expires_at: '2026-09-21T00:25:00+00:00',
        mine: true,
      },
    },
  ],
}

const renderPage = () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <WorkflowControlTowerPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

describe('Enterprise Operational Workspace', () => {
  it('renders the unified authoritative queue and its operating signals', async () => {
    mockedGet.mockResolvedValue([{ id: projectId, name: 'Production' }])
    mockedList.mockResolvedValue(queue)

    renderPage()

    expect(await screen.findByText('Enterprise Operational Workspace')).toBeTruthy()
    expect(await screen.findByText('Governed approval: finding.disposition.accept_risk')).toBeTruthy()
    expect(screen.getByText('Assurance review: recurrence')).toBeTruthy()
    expect(screen.getAllByText('Overdue').length).toBeGreaterThan(0)
    expect(mockedList).toHaveBeenCalledWith({
      project_id: projectId,
      source_type: undefined,
      claim_state: undefined,
      limit: 500,
    })
  })

  it('claims unowned work with authoritative claim CAS and a finite lease', async () => {
    mockedGet.mockResolvedValue([{ id: projectId, name: 'Production' }])
    mockedList.mockResolvedValue(queue)
    mockedClaim.mockResolvedValue({} as never)

    renderPage()

    const claimButton = await screen.findByRole('button', {
      name: 'Claim Governed approval: finding.disposition.accept_risk',
    })
    fireEvent.click(claimButton)

    await waitFor(() => expect(mockedClaim).toHaveBeenCalledWith(
      'governed_action_request',
      '77777777-7777-4777-8777-777777777777',
      {
        project_id: projectId,
        expected_claim_version: 0,
        idempotency_key: 'ops:claim:key-0001',
        lease_seconds: 900,
      },
    ))
    expect(mockedKey).toHaveBeenCalled()
  })

  it('renews and releases only work the server marks as mine', async () => {
    mockedGet.mockResolvedValue([{ id: projectId, name: 'Production' }])
    mockedList.mockResolvedValue(queue)
    mockedRenew.mockResolvedValue({} as never)
    mockedRelease.mockResolvedValue({} as never)

    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: 'Renew Assurance review: recurrence' }))
    await waitFor(() => expect(mockedRenew).toHaveBeenCalledWith(
      'assurance_obligation',
      '88888888-8888-4888-8888-888888888888',
      expect.objectContaining({
        project_id: projectId,
        expected_claim_version: 4,
        lease_seconds: 900,
      }),
    ))

    fireEvent.click(screen.getByRole('button', { name: 'Release Assurance review: recurrence' }))
    await waitFor(() => expect(mockedRelease).toHaveBeenCalledWith(
      'assurance_obligation',
      '88888888-8888-4888-8888-888888888888',
      expect.objectContaining({
        project_id: projectId,
        expected_claim_version: 4,
      }),
    ))
  })
})
