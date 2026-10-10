// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AxiosError, AxiosHeaders, type InternalAxiosRequestConfig } from 'axios'
import { api } from '@/services/api'
import { initAuth, useAuthStore } from './authStore'

const unauthorized = (path: string, status = 401, requestConfig?: InternalAxiosRequestConfig) => {
  const config = requestConfig ?? { url: path, method: 'get', headers: new AxiosHeaders() }
  return new AxiosError('rejected', 'ERR_BAD_RESPONSE', config, undefined, {
    data: {}, status, statusText: 'Rejected', headers: {}, config,
  })
}

describe('single-path owner and employee session recovery', () => {
  beforeEach(() => {
    window.localStorage.clear()
    useAuthStore.setState({
      user: null, isAuthenticated: false, loading: true,
      initialized: false, error: null,
    })
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('does not start a second refresh if bootstrap receives a definitive 401', async () => {
    window.localStorage.setItem('aegis-session-active', '1')
    useAuthStore.setState({ isAuthenticated: true })
    const get = vi.spyOn(api, 'get').mockImplementation(async (url) => {
      if (url === '/auth/csrf/') return { data: {} } as never
      throw unauthorized(String(url))
    })
    const refresh = vi.fn(async () => { throw new Error('duplicate refresh is forbidden') })
    useAuthStore.setState({ refreshAccessToken: refresh })
    await initAuth()
    expect(get).toHaveBeenCalledTimes(2)
    expect(refresh).not.toHaveBeenCalled()
    expect(window.localStorage.getItem('aegis-session-active')).toBeNull()
    expect(useAuthStore.getState()).toMatchObject({ user: null, isAuthenticated: false, initialized: true, loading: false })
  })

  it('preserves session hint during a temporary bootstrap outage', async () => {
    window.localStorage.setItem('aegis-session-active', '1')
    useAuthStore.setState({ isAuthenticated: true })
    vi.spyOn(api, 'get').mockRejectedValue(new Error('temporary proxy outage'))
    await initAuth()
    expect(window.localStorage.getItem('aegis-session-active')).toBe('1')
    expect(useAuthStore.getState()).toMatchObject({ isAuthenticated: true, initialized: true, loading: false })
  })

  it('removes stale session hint when the one refresh request is rejected with 401', async () => {
    window.localStorage.setItem('aegis-session-active', '1')
    useAuthStore.setState({
      isAuthenticated: true,
      refreshAccessToken: vi.fn(async () => { throw unauthorized('/auth/refresh/') }),
    })
    await expect(api.get('/projects/', { adapter: async config => { throw unauthorized(String(config.url), 401, config) } })).rejects.toBeTruthy()
    expect(window.localStorage.getItem('aegis-session-active')).toBeNull()
    expect(useAuthStore.getState().isAuthenticated).toBe(false)
  })

  it('does not log out automatically if refresh hits a temporary 503', async () => {
    window.localStorage.setItem('aegis-session-active', '1')
    useAuthStore.setState({
      isAuthenticated: true,
      refreshAccessToken: vi.fn(async () => { throw unauthorized('/auth/refresh/', 503) }),
    })
    await expect(api.get('/projects/', { adapter: async config => { throw unauthorized(String(config.url), 401, config) } })).rejects.toBeTruthy()
    expect(window.localStorage.getItem('aegis-session-active')).toBe('1')
    expect(useAuthStore.getState().isAuthenticated).toBe(true)
  })

  it('invalidates client session after a refreshed request is still unauthorized', async () => {
    window.localStorage.setItem('aegis-session-active', '1')
    useAuthStore.setState({
      isAuthenticated: true,
      refreshAccessToken: vi.fn(async () => undefined),
    })
    await expect(api.get('/projects/', { adapter: async config => { throw unauthorized(String(config.url), 401, config) } })).rejects.toBeTruthy()
    expect(window.localStorage.getItem('aegis-session-active')).toBeNull()
    expect(useAuthStore.getState().isAuthenticated).toBe(false)
  })
})
