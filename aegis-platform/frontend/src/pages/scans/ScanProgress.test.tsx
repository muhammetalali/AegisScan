// @vitest-environment jsdom
import { act, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  createWebSocket: vi.fn(),
}))

vi.mock('@/services/api', () => ({
  apiHelpers: { get: api.get, post: api.post },
  createWebSocket: api.createWebSocket,
}))
vi.mock('@/stores/languageStore', () => ({
  useLanguageStore: (selector: (s: {t: (key: string) => string}) => unknown) =>
    selector({ t: (key: string) => key }),
}))

import { ScanProgress } from './ScanProgress'

class StubWebSocket {
  onopen: (() => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((event: {data: string}) => void) | null = null
  close = vi.fn()
  send(payload: Record<string, unknown>) {
    act(() => { this.onmessage?.({ data: JSON.stringify(payload) }) })
  }
}

const scan = {
  id: 'scan-001', project_id: 'project-001', name: 'Authorized test',
  scan_type: 'ip', status: 'running', progress: 0, current_phase: 'nmap',
  security_score: 0, risk_level: 'unknown', findings_count: 0,
  created_at: '2026-10-08T10:00:00Z',
}

let socket: StubWebSocket

beforeEach(() => {
  api.get.mockReset()
  api.post.mockReset()
  api.createWebSocket.mockReset()
  socket = new StubWebSocket()
  api.createWebSocket.mockReturnValue(socket)
  api.get.mockImplementation(async (path: string) =>
    path.includes('engine-executions') ? [] : scan
  )
})

function mount() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/scan/scan-001']}>
        <Routes><Route path="/scan/:id" element={<ScanProgress />} /></Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('scan progress resource efficiency', () => {
  it('renders WebSocket frames without restarting both API fetches per frame', async () => {
    mount()
    await screen.findByText('Authorized test')
    expect(api.get).toHaveBeenCalledTimes(2)
    act(() => { socket.onopen?.() })
    for (let progress = 1; progress <= 10; progress++) {
      socket.send({ status: 'running', progress, current_phase: 'nmap' })
    }
    expect(api.get).toHaveBeenCalledTimes(2)
    expect(screen.getAllByText('10%').length).toBeGreaterThan(0)
  })

  it('refreshes persisted scan and executions once on terminal event', async () => {
    mount()
    await screen.findByText('Authorized test')
    act(() => { socket.onopen?.() })
    socket.send({ status: 'completed', progress: 100 })
    socket.send({ status: 'completed', progress: 100 })
    await waitFor(() => expect(api.get).toHaveBeenCalledTimes(4))
    expect(socket.close).not.toHaveBeenCalled()
  })
})
