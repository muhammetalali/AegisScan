// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
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

const renderPage = () => {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={queryClient}>
    <MemoryRouter initialEntries={['/assets']}>
      <Routes>
        <Route path="/assets" element={<Assets />} />
        <Route path="/scan/:id/progress" element={<div>Scan progress</div>} />
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
  it('uses the canonical asset scan route without requesting ports or a second target', async () => {
    renderPage()
    const button = await screen.findByRole('button', { name: 'Scan Permitted lab IP' })
    fireEvent.click(button)
    await waitFor(() => expect(post).toHaveBeenCalledWith('/assets/asset-existing/scan'))
    await waitFor(() => expect(screen.getByText('Scan progress')).toBeTruthy())
  })

  it('does not offer scan execution for inactive assets', async () => {
    get.mockResolvedValue([{ ...permittedAsset, is_active: false }])
    renderPage()
    expect(await screen.findByRole('button', { name: 'Scan Permitted lab IP' })).toHaveProperty('disabled', true)
    expect(post).not.toHaveBeenCalled()
  })
})
