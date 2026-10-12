// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { NewValidation } from './NewValidation'
import { apiHelpers } from '@/services/api'
import { CATALOGS, useLanguageStore } from '@/stores/languageStore'

vi.mock('@/services/api', () => ({
  apiHelpers: { get: vi.fn(), post: vi.fn() },
}))
const get = vi.mocked(apiHelpers.get)
const post = vi.mocked(apiHelpers.post)

beforeEach(() => {
  useLanguageStore.setState({ language: 'en', translations: CATALOGS.en })
  get.mockResolvedValue([{ id: 'finding-1', title: 'Known network finding', severity: 'high',
    status: 'open', source_engine: 'nmap', asset_target: '192.0.2.15', asset_id: 'asset-1' }])
  post.mockResolvedValue({ id: 'validation-1', finding_id: 'finding-1' })
})
afterEach(() => vi.clearAllMocks())

describe('NewValidation derives target from persisted finding', () => {
  it('removes redundant manual scope step and submits the existing target', async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/validations/new']}>
        <Routes>
          <Route path="/validations/new" element={<NewValidation />} />
          <Route path="/validations/:id/progress" element={<div>Validation progress</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>)

    await waitFor(() => expect(screen.getByText('Known network finding')).toBeTruthy())
    fireEvent.click(screen.getByText('Known network finding'))
    fireEvent.click(screen.getByRole('button', { name: /continue/i }))
    expect(screen.getByText('Preserve the assessment criteria')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /continue/i }))
    expect(screen.getByText('Review the real execution contract')).toBeTruthy()
    expect(screen.queryByText('Scope & safety')).toBeNull()
    expect(screen.queryByRole('textbox', { name: /authorized scope/i })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /create validation job/i }))

    await waitFor(() => expect(post).toHaveBeenCalledWith('/validations', expect.objectContaining({
      finding_id: 'finding-1', target_type: 'ip', target_value: '192.0.2.15',
      scope: '192.0.2.15', include_subdomains: false, engines: ['nmap'],
    })))
    await waitFor(() => expect(screen.getByText('Validation progress')).toBeTruthy())
  })
})
