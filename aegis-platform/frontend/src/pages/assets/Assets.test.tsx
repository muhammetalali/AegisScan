// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { Assets } from './Assets'
import { apiHelpers } from '@/services/api'
import { CATALOGS, useLanguageStore } from '@/stores/languageStore'

vi.mock('@/services/api', () => ({
  apiHelpers: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}))

const get = vi.mocked(apiHelpers.get)
const post = vi.mocked(apiHelpers.post)
const permittedAsset = {
  id: 'asset-existing', name: 'Permitted lab IP', slug: 'permitted-lab-ip',
  type: 'ip_address', project_id: 'project-existing', environment: 'development',
  criticality: 'medium', is_active: true, configuration: { ip: '192.0.2.50' },
  tags: [], scan_count: 0, created_at: '2026-10-12T00:00:00Z',
  updated_at: '2026-10-12T00:00:00Z',
}

const ScanPickerResult = () => { const location = useLocation(); return <div>Scan picker: {location.search}</div> }

const renderPage = () => {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={queryClient}>
    <MemoryRouter initialEntries={['/assets']}>
      <Routes>
        <Route path="/assets" element={<Assets />} />
        <Route path="/scan" element={<ScanPickerResult />} />
      </Routes>
    </MemoryRouter>
  </QueryClientProvider>)
}

beforeEach(() => {
  useLanguageStore.setState({ language: 'en', translations: CATALOGS.en })
  get.mockResolvedValue([permittedAsset])
  post.mockResolvedValue({ scan_id: 'scan-existing' })
})
afterEach(() => vi.clearAllMocks())

describe('Assets existing authorization one-click scan', () => {
  it('opens the existing scan picker with project and asset preselected', async () => {
    renderPage()
    const button = await screen.findByRole('button', { name: 'Scan Permitted lab IP' })
    fireEvent.click(button)
    expect(await screen.findByText('Scan picker: ?project_id=project-existing&asset_id=asset-existing')).toBeTruthy()
    expect(post).not.toHaveBeenCalled()
  })


  it('reads discovered services and linked assets through the existing APIs', async () => {
    get.mockImplementation(async (url: string) => {
      if (url === '/assets/') return [permittedAsset]
      if (url === '/assets/asset-existing/technologies') return [{
        id: 'svc-1', name: 'nginx tcp/443', version: '1.2',
        category: 'network_service', source: 'nmap',
      }]
      if (url === '/assets/asset-existing/relationships') return [{
        id: 'link-1', target_id: 'related-ip-id', relationship_type: 'contains',
      }]
      throw new Error(`Unexpected request: ${url}`)
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Permitted lab IP' }))
    await waitFor(() => expect(get).toHaveBeenCalledWith('/assets/asset-existing/technologies'))
    await waitFor(() => expect(get).toHaveBeenCalledWith('/assets/asset-existing/relationships'))
    expect(await screen.findByText('nginx tcp/443')).toBeTruthy()
    expect(await screen.findByText('related-ip-id')).toBeTruthy()
  })

  it('does not offer scan execution for inactive assets', async () => {
    get.mockResolvedValue([{ ...permittedAsset, is_active: false }])
    renderPage()
    expect(await screen.findByRole('button', { name: 'Scan Permitted lab IP' })).toHaveProperty('disabled', true)
    expect(post).not.toHaveBeenCalled()
  })
})
