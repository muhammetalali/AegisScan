// @vitest-environment jsdom
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { api } from './services/api'
import { useAuthStore } from './stores/authStore'
import type { User } from './types'

const originalFetchUser = useAuthStore.getState().fetchUser
let ProtectedRoute: typeof import('./App')['ProtectedRoute']
beforeAll(async () => {
  // jsdom does not implement the theme listener used by the existing App.
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: false, media: query, onchange: null,
    addListener: vi.fn(), removeListener: vi.fn(),
    addEventListener: vi.fn(), removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }))
  ;({ ProtectedRoute } = await import('./App'))
})

describe('protected route after temporary session restoration outage', () => {
  beforeEach(() => {
    useAuthStore.setState({
      isAuthenticated: true, initialized: true, loading: false, user: null,
    })
  })
  afterEach(() => {
    cleanup()
    useAuthStore.setState({ fetchUser: originalFetchUser })
    vi.restoreAllMocks()
  })

  it('shows a retry action instead of mislabeling a network outage as an RBAC 403', () => {
    render(<MemoryRouter initialEntries={['/dashboard']}><ProtectedRoute><div>Dashboard content</div></ProtectedRoute></MemoryRouter>)
    expect(screen.getByRole('alert').textContent).toContain('temporarily unavailable')
    expect(screen.queryByText('403 · Access denied')).toBeNull()
    expect(screen.getByRole('button', { name: 'Retry session' })).toBeTruthy()
  })

  it('retries the existing session check and restores the workspace without another login form', async () => {
    const csrf = vi.spyOn(api, 'get').mockResolvedValue({ data: {} } as never)
    const user = { role: 'viewer', is_company_owner: false, permissions: ['scan.read'], enabled_pages: ['/dashboard'] } as User
    const fetchUser = vi.fn(async () => useAuthStore.setState({ user, isAuthenticated: true }))
    useAuthStore.setState({ fetchUser })
    render(<MemoryRouter initialEntries={['/dashboard']}><ProtectedRoute><div>Dashboard content</div></ProtectedRoute></MemoryRouter>)
    fireEvent.click(screen.getByRole('button', { name: 'Retry session' }))
    await waitFor(() => expect(screen.getByText('Dashboard content')).toBeTruthy())
    expect(csrf).toHaveBeenCalledWith('/auth/csrf/')
    expect(fetchUser).toHaveBeenCalledTimes(1)
  })
})
