// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('@/services/api', () => ({ apiHelpers: { get: api.get } }))
vi.mock('@/stores/languageStore', () => ({
  useLanguageStore: (selector: (s: { t: (key: string) => string }) => unknown) => selector({ t: (key: string) => key }),
}))
import { ScanResults } from './ScanResults'

const scan = {
  id: 'scan-137', project_id: 'project-1', asset_id: 'asset-137',
  name: 'Issue415 controlled lab host137 Nmap service acceptance',
  scan_type: 'ip', status: 'completed', progress: 100, current_phase: 'nmap',
  security_score: 0, risk_level: 'unknown', findings_count: 23,
  created_at: '2026-10-20T00:00:00Z',
}
const evidence = [{ id: 'ev-1', source: 'nmap', evidence_type: 'scanner_output', sha256: 'a'.repeat(64), finding_id: 'finding-1', collected_at: '2026-10-20T00:00:00Z' }]
const findings = [{ id: 'finding-1', title: 'Exposed TCP port 8180 (http)', severity: 'info', status: 'open', source_engine: 'nmap' }]
const executions = [{ id: 'execution-1', engine: 'nmap', status: 'completed', progress: 100, findings_found: 23, evidences_collected: 1 }]

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/scan/scan-137/results']}>
        <Routes><Route path="/scan/:id/results" element={<ScanResults />} /></Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => cleanup())

beforeEach(() => {
  api.get.mockReset()
  api.get.mockImplementation(async (path: string) => {
    if (path === '/scans/scan-137') return scan
    if (path === '/assets/asset-137') return { id: 'asset-137', name: scan.name, type: 'ip_address', configuration: { ip: '192.168.49.137' } }
    if (path.startsWith('/vulnerabilities/')) return findings
    if (path.startsWith('/evidence/')) return evidence
    if (path.includes('/engine-executions')) return executions
    throw new Error('Unexpected API request: ' + path)
  })
})

describe('simple scan identity and evidence UI', () => {
  it('uses authorized asset IP as the primary title, not the internal scan name or UUID', async () => {
    mount()
    expect(await screen.findByRole('heading', { name: '192.168.49.137' })).toBeTruthy()
    expect(screen.getByText('Not recorded')).toBeTruthy()
    expect(screen.getByText('Not assessed')).toBeTruthy()
    expect(screen.getByText('An exposed port is not automatically a confirmed vulnerability.')).toBeTruthy()
    expect(screen.getByText('Exposed TCP port 8180 (http)')).toBeTruthy()
    expect(await screen.findByText(/View evidence records/)).toBeTruthy()
    expect(screen.getByText('Technical details')).toBeTruthy()
    const title = screen.getByRole('heading', { name: '192.168.49.137' })
    expect(title.textContent).not.toContain(scan.name)
  })

  it('uses a verified MAC only when the saved asset field is well-formed', async () => {
    api.get.mockImplementation(async (path: string) => path === '/scans/scan-137' ? scan :
      path === '/assets/asset-137' ? { configuration: { ip: '192.168.49.137', mac_address: '00:0c:29:3c:3d:ea' } } :
      path.includes('engine-executions') ? executions : [])
    mount()
    await waitFor(() => expect(screen.getByText('00:0C:29:3C:3D:EA')).toBeTruthy())
  })

  it('never substitutes a verbose scan title for a missing network identity', async () => {
    api.get.mockImplementation(async (path: string) => {
      if (path === '/scans/scan-137') return { ...scan, asset_id: null }
      if (path.includes('engine-executions')) return executions
      return []
    })
    mount()
    expect(await screen.findByRole('heading', { name: 'Target not recorded' })).toBeTruthy()
    expect(api.get).not.toHaveBeenCalledWith('/assets/asset-137')
  })

  it('does not render scan data after an access denial', async () => {
    api.get.mockRejectedValue(new Error('404'))
    mount()
    expect(await screen.findByRole('heading', { name: 'Unable to load scan' })).toBeTruthy()
    expect(screen.queryByText(scan.name)).toBeNull()
    expect(screen.queryByText('192.168.49.137')).toBeNull()
  })
})
