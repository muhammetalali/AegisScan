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

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } })
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/scan']}>
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
})
