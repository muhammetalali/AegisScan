// @vitest-environment jsdom
import { render, screen, waitFor, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('@/services/api', () => ({ apiHelpers: { get: api.get } }))
import { AssuranceGraphPage } from './AssuranceGraphPage'
afterEach(() => { cleanup(); api.get.mockReset() })

describe('live assurance page smoke regression', () => {
  it('renders current aggregator response rather than throwing on kind and source/target', async () => {
    api.get.mockResolvedValue({
      nodes: [
        { id: 'validation:123', kind: 'validation', label: 'Lab check', status: 'completed', risk: 10, confidence: 85, validationId: '123' },
        { id: 'engine:nmap', kind: 'engine', label: 'Nmap engine', status: 'active', risk: 0, confidence: 95 },
      ],
      edges: [{ source: 'validation:123', target: 'engine:nmap', relation: 'validated-by' }],
      intelligence: { topPriorityNodes: [], attackPriorityPaths: [], executivePriority: 15, riskExposure: 30, highImpactNodes: 0, conflictedNodes: 0, evidenceBackedNodes: 1 },
    })
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={client}><AssuranceGraphPage /></QueryClientProvider>)
    expect(await screen.findByRole('heading', { name: 'Unified Assurance Graph' })).toBeTruthy()
    expect(screen.getByText('Nmap engine')).toBeTruthy()
    expect(screen.getAllByText('Lab check').length).toBeGreaterThan(0)
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/assurance/graph'))
  })
})
