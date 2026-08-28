// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '@/services/api'
import type { User } from '@/types'
import { useAuthStore } from './authStore'

const post = vi.spyOn(api, 'post')
const get = vi.spyOn(api, 'get')

const user = {
  id: '1', email: 'analyst@example.com', first_name: 'Security', last_name: 'Analyst', role: 'security_analyst',
  permissions: ['dashboard.view'], is_active: true, is_verified: true, language: 'en', theme: 'system', timezone: 'UTC',
  two_factor_enabled: false, date_joined: '2026-01-01T00:00:00Z',
} satisfies User

beforeEach(() => {
  post.mockReset()
  get.mockReset()
  localStorage.clear()
  sessionStorage.clear()
  useAuthStore.setState({ user: null, accessToken: null, refreshToken: null, isAuthenticated: false, loading: false, error: null })
})

describe('authentication lifecycle', () => {
  it('returns explicit 2FA state without authenticating the session', async () => {
    post.mockResolvedValueOnce({ data: { detail: 'Two-factor authentication code required', two_factor_required: true } } as never)

    const requires2FA = await useAuthStore.getState().login('analyst@example.com', 'password123', true)

    expect(requires2FA).toBe(true)
    expect(useAuthStore.getState().isAuthenticated).toBe(false)
    expect(useAuthStore.getState().accessToken).toBeNull()
  })

  it('stores a rotated refresh token when the server returns one', async () => {
    post.mockResolvedValueOnce({ data: { access: 'access-1', refresh: 'refresh-1', user } } as never)
    await useAuthStore.getState().login('analyst@example.com', 'password123', true)

    post.mockResolvedValueOnce({ data: { access: 'access-2', refresh: 'refresh-2' } } as never)
    await useAuthStore.getState().refreshAccessToken()

    expect(useAuthStore.getState().accessToken).toBe('access-2')
    expect(useAuthStore.getState().refreshToken).toBe('refresh-2')
    expect(useAuthStore.getState().isAuthenticated).toBe(true)
  })

  it('boots an authenticated session by validating the access token', async () => {
    useAuthStore.setState({ user, accessToken: 'access-1', refreshToken: 'refresh-1', isAuthenticated: true, loading: false, error: null })
    get.mockResolvedValueOnce({ data: user } as never)

    await useAuthStore.getState().fetchUser()

    expect(get).toHaveBeenCalledWith('/users/me/')
    expect(useAuthStore.getState().user?.email).toBe('analyst@example.com')
  })
})
