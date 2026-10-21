// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), delete: vi.fn() }))
vi.mock('@/services/api', () => ({ apiHelpers: api }))
vi.mock('@/stores/languageStore', () => ({
  useLanguageStore: (select: (s: {t: (key: string) => string}) => unknown) => select({ t: (key: string) => key }),
}))
import { ScanPage } from './ScanPage'

const first = { id: 'e2e-1', name: 'External E2E fixture 1', status: 'active' }
const actual = { id: 'real-1', name: 'mi-kali', status: 'active' }

function mount(entry = '/scan') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } })
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}>
    <Routes><Route path="/scan" element={<ScanPage />} /></Routes>
  </MemoryRouter></QueryClientProvider>)
}

afterEach(cleanup)
beforeEach(() => {
  api.get.mockReset()
  api.get.mockImplementation(async (path: string, opts?: {params?: {page?: number}}) => {
    if (path === '/scans/?limit=100') return []
    if (path === '/projects/') return Number(opts?.params?.page) === 1
      ? { count: 2, next: '/api/v1/projects/?page=2', results: [first] }
      : { count: 2, next: null, results: [actual] }
    throw new Error('Unexpected request: ' + path)
  })
})

describe('governed Scan registry project picker', () => {
  it('renders a real paginated project list without crashing on first-page object', async () => {
    mount()
    expect(await screen.findByText('No scans available')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'New scan' }))
    await waitFor(() => expect(screen.getByRole('option', { name: 'mi-kali' })).toBeTruthy())
    expect(screen.queryByRole('option', { name: /External E2E/ })).toBeNull()
    expect(api.get).toHaveBeenCalledWith('/projects/', { params: { page: 2 } })
  })
  it('keeps network.nmap available when the live plan includes pending_provider_runtime', async () => {
    api.get.mockImplementation(async (path: string) => {
      if (path === '/scans/?limit=100') return []
      if (path === '/projects/') return { count: 1, next: null, results: [actual] }
      if (path === '/assets/') return [{
        id: 'asset-cidr', project_id: 'real-1', name: '192.168.49.0/24',
        type: 'network_range', is_active: true, configuration: { cidr: '192.168.49.0/24' },
      }]
      if (path === '/capabilities/plan/asset-cidr') return {
        policy_version: 'capability-execution.v4',
        asset_type: 'network_range', depth: 'standard',
        total: 1, ready: 1, pending_packaging: 0, pending_provider_runtime: 0,
        plan: [{
          capability_id: 'network.nmap', tool: 'nmap',
          category: 'network-reconnaissance', risk: 'active-low',
          execution_ready: true, reason: 'packaged and eligible for governed execution', order: 1,
        }],
      }
      throw new Error('Unexpected request: ' + path)
    })
    mount('/scan?project_id=real-1&asset_id=asset-cidr')
    expect(await screen.findByRole('option', { name: /network\.nmap/ })).toBeTruthy()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Run capability' }).hasAttribute('disabled')).toBe(false))
  })

  it('shows an actionable error and safely retries a failed capability plan', async () => {
    let attempts = 0
    api.post.mockReset()
    api.get.mockImplementation(async (path: string) => {
      if (path === '/scans/?limit=100') return []
      if (path === '/projects/') return { count: 1, next: null, results: [actual] }
      if (path === '/assets/') return [{
        id: 'asset-cidr', project_id: 'real-1', name: '192.168.49.0/24',
        type: 'network_range', is_active: true, configuration: { cidr: '192.168.49.0/24' },
      }]
      if (path === '/capabilities/plan/asset-cidr') {
        attempts += 1
        if (attempts === 1) throw new Error('Temporary capability plan failure')
        return {
          policy_version: 'capability-execution.v4',
          asset_type: 'network_range', depth: 'standard',
          total: 1, ready: 1, pending_packaging: 0, pending_provider_runtime: 0,
          plan: [{
            capability_id: 'network.nmap', tool: 'nmap',
            category: 'network-reconnaissance', risk: 'active-low',
            execution_ready: true, reason: 'packaged and eligible for governed execution', order: 1,
          }],
        }
      }
      throw new Error('Unexpected request: ' + path)
    })
    mount('/scan?project_id=real-1&asset_id=asset-cidr')
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('Unable to load available scan capabilities.'))
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('option', { name: /network\.nmap/ })).toBeTruthy()
    expect(api.post).not.toHaveBeenCalled()
  })

  it('mounts the scan dialog at document body, outside route stacking contexts, and closes without scheduling', async () => {
    api.post.mockReset()
    mount()
    expect(await screen.findByText('No scans available')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'New scan' }))
    const dialog = await screen.findByRole('dialog', { name: 'New scan' })
    expect(dialog.parentElement).toBe(document.body)
    expect(dialog.getAttribute('aria-modal')).toBe('true')
    expect(screen.getByRole('button', { name: 'Run capability' }).hasAttribute('disabled')).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(api.post).not.toHaveBeenCalled()
  })

})
