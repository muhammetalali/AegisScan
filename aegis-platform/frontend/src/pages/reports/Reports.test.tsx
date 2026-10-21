// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }))
vi.mock('@/services/api', () => ({ apiHelpers: api }))
vi.mock('@/stores/languageStore', () => ({
  useLanguageStore: (select: (s: {t: (key: string) => string}) => unknown) => select({ t: (key: string) => key }),
}))
import { Reports } from './Reports'

beforeEach(() => {
  api.get.mockReset()
  api.post.mockReset()
  api.get.mockImplementation(async (path: string, config?: {params?: {page?: number}}) => {
    if (path === '/reports/?limit=100') return []
    if (path === '/dashboard/summary') return {}
    if (path === '/dashboard/risk-distribution') return {}
    if (path.startsWith('/scans/?project_id=')) {
      const projectId = path.split('project_id=')[1]?.split('&')[0]
      const offset = Number(path.split('offset=')[1] ?? 0)
      if (projectId === 'second' && offset === 0)
        return Array.from({ length: 100 }, (_, i) => ({ id: 'early-' + i, name: 'Previous scan ' + i, project_id: 'second', status: 'completed' }))
      if (projectId === 'second' && offset === 100)
        return [{ id: 'f4fb9b75-c98d-4cf9-b471-0c200c6d5971', name: 'CIDR 192.168.49.0/24', project_id: 'second', status: 'completed' }]
      if (projectId === 'first') return [{ id: 'other-project-scan', name: 'Unrelated scan', project_id: 'first', status: 'completed' }]
      return []
    }
    if (path === '/projects/') return Number(config?.params?.page) === 1
      ? { count: 2, next: '/api/v1/projects/?page=2',
          results: [{ id: 'first', name: 'First page project', status: 'active' }] }
      : { count: 2, next: null,
          results: [{ id: 'second', name: 'Late page project', status: 'active' }] }
    throw new Error('Unexpected API path ' + path)
  })
})
afterEach(cleanup)

describe('report generator project picker', () => {
  it('exposes owner projects across DRF pagination without creating duplicate projects or reports', async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={client}><MemoryRouter><Reports /></MemoryRouter></QueryClientProvider>)
    expect(await screen.findByText('Report center')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Generate report' }))
    expect(await screen.findByRole('option', { name: 'Late page project' })).toBeTruthy()
    expect(screen.getByRole('option', { name: 'First page project' })).toBeTruthy()
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/projects/', { params: { page: 2 } }))
    expect(api.post).not.toHaveBeenCalled()
  })
  it('portals the report dialog outside page motion containers and keeps it scrollable', async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={client}><MemoryRouter><Reports /></MemoryRouter></QueryClientProvider>)
    fireEvent.click(await screen.findByRole('button', { name: 'Generate report' }))
    const dialog = await screen.findByRole('dialog', { name: 'Generate report' })
    expect(dialog.parentElement).toBe(document.body)
    expect(dialog.getAttribute('aria-modal')).toBe('true')
    expect(dialog.className).toContain('overflow-y-auto')
    const card = dialog.querySelector('.enterprise-card')
    expect(card?.className).toContain('max-h-[calc(100vh-2rem)]')
    expect(api.post).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  it('creates one report bound to the selected scan on the second scan page, and resets it on project change', async () => {
    api.post.mockResolvedValue({ id: 'report-bound-to-scan', scan_id: 'f4fb9b75-c98d-4cf9-b471-0c200c6d5971' })
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={client}><MemoryRouter><Reports /></MemoryRouter></QueryClientProvider>)
    fireEvent.click(await screen.findByRole('button', { name: 'Generate report' }))
    const dialog = await screen.findByRole('dialog', { name: 'Generate report' })
    fireEvent.change(screen.getByLabelText('Project'), { target: { value: 'second' } })
    const exactScan = await screen.findByRole('option', { name: 'CIDR 192.168.49.0/24 · completed' })
    expect(exactScan).toBeTruthy()
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/scans/?project_id=second&limit=100&offset=100'))
    fireEvent.change(screen.getByLabelText('Scan'), { target: { value: 'f4fb9b75-c98d-4cf9-b471-0c200c6d5971' } })
    fireEvent.change(screen.getByLabelText('Project'), { target: { value: 'first' } })
    expect((screen.getByLabelText('Scan') as HTMLSelectElement).value).toBe('')
    await screen.findByRole('option', { name: 'Unrelated scan · completed' })
    fireEvent.change(screen.getByLabelText('Project'), { target: { value: 'second' } })
    await screen.findByRole('option', { name: 'CIDR 192.168.49.0/24 · completed' })
    fireEvent.change(screen.getByLabelText('Scan'), { target: { value: 'f4fb9b75-c98d-4cf9-b471-0c200c6d5971' } })
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Issue415 final CIDR scan report' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Generate report' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1))
    expect(api.post).toHaveBeenCalledWith('/reports/', {
      project_id: 'second', scan_id: 'f4fb9b75-c98d-4cf9-b471-0c200c6d5971',
      title: 'Issue415 final CIDR scan report', description: '', report_type: 'full',
      format: 'pdf', template_id: 'full',
    })
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

})
