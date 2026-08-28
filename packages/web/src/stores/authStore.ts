import React, { useEffect, useState } from 'react'
import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import { api } from '@/services/api'
import type { User } from '@/types'

interface AuthState {
  user: User | null
  accessToken: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  loading: boolean
  error: string | null
  login: (email: string, password: string, rememberMe?: boolean, otp?: string) => Promise<boolean>
  register: (data: RegisterData) => Promise<void>
  logout: () => Promise<void>
  refreshAccessToken: () => Promise<void>
  forgotPassword: (email: string) => Promise<void>
  resetPassword: (token: string, password: string) => Promise<void>
  verifyEmail: (token: string) => Promise<void>
  resendVerification: () => Promise<void>
  updateProfile: (data: Partial<User>) => Promise<void>
  changePassword: (oldPassword: string, newPassword: string) => Promise<void>
  enable2FA: () => Promise<{ secret: string; qrCode: string; otpauthUri: string }>
  verify2FA: (code: string) => Promise<void>
  disable2FA: (password: string, code: string) => Promise<void>
  fetchUser: () => Promise<void>
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
}

interface RegisterData {
  email: string
  password: string
  password_confirm: string
  first_name: string
  last_name: string
  phone?: string
}

type PersistedAuth = Pick<AuthState, 'user' | 'accessToken' | 'refreshToken' | 'isAuthenticated'>
const AUTH_STORAGE_PREFERENCE = 'aegis-auth-storage'
const AUTH_STORAGE_KEY = 'aegis-auth'

const browserStorage = {
  get preferred() {
    return window.localStorage.getItem(AUTH_STORAGE_PREFERENCE) === 'session' ? window.sessionStorage : window.localStorage
  },
  setPreference(mode: 'local' | 'session') { window.localStorage.setItem(AUTH_STORAGE_PREFERENCE, mode) },
  clearAll() {
    window.localStorage.removeItem(AUTH_STORAGE_KEY)
    window.sessionStorage.removeItem(AUTH_STORAGE_KEY)
    window.localStorage.removeItem(AUTH_STORAGE_PREFERENCE)
  },
}

const clearAuthorization = () => { delete api.defaults.headers.common.Authorization }
const applyAuthorization = (token: string) => { api.defaults.headers.common.Authorization = `Bearer ${token}` }

const extractApiMessage = (error: unknown, fallback: string): string => {
  const response = (error as { response?: { data?: unknown } })?.response?.data
  if (typeof response === 'string' && response.trim()) return response
  if (response && typeof response === 'object') {
    const data = response as Record<string, unknown>
    const nested = data.error
    if (nested && typeof nested === 'object' && typeof (nested as Record<string, unknown>).message === 'string') return String((nested as Record<string, unknown>).message)
    for (const key of ['detail', 'message', 'error']) if (typeof data[key] === 'string' && String(data[key]).trim()) return String(data[key])
    const fieldMessage = Object.values(data).find((value) => Array.isArray(value) && value.length && typeof value[0] === 'string')
    if (Array.isArray(fieldMessage) && fieldMessage[0]) return String(fieldMessage[0])
  }
  if (error instanceof Error && error.message) return error.message
  return fallback
}

export const useAuthStore = create<AuthState>()(persist((set, get) => ({
  user: null, accessToken: null, refreshToken: null, isAuthenticated: false, loading: false, error: null,
  setLoading: (loading) => set({ loading }), setError: (error) => set({ error }),

  login: async (email, password, rememberMe = true, otp) => {
    set({ loading: true, error: null })
    try {
      const { data } = await api.post('/auth/login/', { email: email.trim().toLowerCase(), password, ...(otp ? { otp } : {}) })
      if (data?.two_factor_required && !data?.access) { set({ loading: false }); return true }
      if (!data?.access || !data?.refresh || !data?.user) throw new Error('Invalid login response')
      browserStorage.setPreference(rememberMe ? 'local' : 'session')
      ;(rememberMe ? window.sessionStorage : window.localStorage).removeItem(AUTH_STORAGE_KEY)
      applyAuthorization(data.access)
      set({ user: data.user, accessToken: data.access, refreshToken: data.refresh, isAuthenticated: true, loading: false })
      return false
    } catch (error) {
      clearAuthorization()
      set({ loading: false, isAuthenticated: false, error: extractApiMessage(error, 'Login failed') })
      throw error
    }
  },

  register: async (data) => {
    set({ loading: true, error: null })
    try {
      const { data: response } = await api.post('/auth/register/', data)
      if (!response?.access || !response?.refresh || !response?.user) throw new Error('Invalid registration response')
      browserStorage.setPreference('local'); window.sessionStorage.removeItem(AUTH_STORAGE_KEY)
      applyAuthorization(response.access)
      set({ user: response.user, accessToken: response.access, refreshToken: response.refresh, isAuthenticated: true, loading: false })
    } catch (error) {
      clearAuthorization(); set({ loading: false, isAuthenticated: false, error: extractApiMessage(error, 'Registration failed') }); throw error
    }
  },

  logout: async () => {
    const { refreshToken } = get()
    try { if (refreshToken) await api.post('/users/logout/', { refresh_token: refreshToken }) }
    catch { /* client teardown must not depend on network availability */ }
    finally {
      clearAuthorization(); browserStorage.clearAll()
      set({ user: null, accessToken: null, refreshToken: null, isAuthenticated: false, loading: false, error: null })
    }
  },

  refreshAccessToken: async () => {
    const { refreshToken } = get()
    if (!refreshToken) throw new Error('No refresh token available')
    try {
      const { data } = await api.post('/auth/refresh/', { refresh: refreshToken })
      if (!data?.access) throw new Error('Invalid refresh response')
      applyAuthorization(data.access)
      set({ accessToken: data.access, refreshToken: data.refresh ?? refreshToken, isAuthenticated: true, error: null })
    } catch (error) {
      clearAuthorization(); browserStorage.clearAll()
      set({ user: null, accessToken: null, refreshToken: null, isAuthenticated: false }); throw error
    }
  },

  forgotPassword: async (email) => { set({ loading: true, error: null }); try { await api.post('/auth/password/reset/', { email: email.trim().toLowerCase() }); set({ loading: false }) } catch (error) { set({ loading: false, error: extractApiMessage(error, 'Failed to send reset email') }); throw error } },
  resetPassword: async (token, password) => { set({ loading: true, error: null }); try { await api.post('/auth/password/reset/confirm/', { token, password }); set({ loading: false }) } catch (error) { set({ loading: false, error: extractApiMessage(error, 'Failed to reset password') }); throw error } },
  verifyEmail: async (token) => { set({ loading: true, error: null }); try { await api.post('/auth/verify-email/', { token }); set({ loading: false }) } catch (error) { set({ loading: false, error: extractApiMessage(error, 'Failed to verify email') }); throw error } },
  resendVerification: async () => { set({ loading: true, error: null }); try { await api.post('/auth/resend-verification/'); set({ loading: false }) } catch (error) { set({ loading: false, error: extractApiMessage(error, 'Failed to resend verification') }); throw error } },
  updateProfile: async (data) => { set({ loading: true, error: null }); try { const response = await api.patch('/users/me/', data); set({ user: response.data, loading: false }) } catch (error) { set({ loading: false, error: extractApiMessage(error, 'Failed to update profile') }); throw error } },
  changePassword: async (oldPassword, newPassword) => { set({ loading: true, error: null }); try { await api.post('/users/change_password/', { old_password: oldPassword, new_password: newPassword, new_password_confirm: newPassword }); set({ loading: false }) } catch (error) { set({ loading: false, error: extractApiMessage(error, 'Failed to change password') }); throw error } },
  enable2FA: async () => (await api.post('/auth/2fa/enable/')).data,
  verify2FA: async (code) => { await api.post('/auth/2fa/verify/', { code }); await get().fetchUser() },
  disable2FA: async (password, code) => { await api.post('/auth/2fa/disable/', { password, code }); await get().fetchUser() },
  fetchUser: async () => { const response = await api.get('/users/me/'); if (!response.data) throw new Error('Invalid user response'); set({ user: response.data, isAuthenticated: true, error: null }) },
}), {
  name: AUTH_STORAGE_KEY,
  storage: createJSONStorage<PersistedAuth>(() => ({
    getItem: () => browserStorage.preferred.getItem(AUTH_STORAGE_KEY),
    setItem: (_name, value) => browserStorage.preferred.setItem(AUTH_STORAGE_KEY, value),
    removeItem: () => browserStorage.preferred.removeItem(AUTH_STORAGE_KEY),
  })),
  partialize: (state) => ({ user: state.user, accessToken: state.accessToken, refreshToken: state.refreshToken, isAuthenticated: state.isAuthenticated }),
}))

export const useAuth = () => useAuthStore()

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [ready, setReady] = useState(false)
  useEffect(() => {
    let active = true
    const bootstrap = async () => {
      const { accessToken, refreshToken, fetchUser, refreshAccessToken, logout, setLoading } = useAuthStore.getState()
      setLoading(true)
      try {
        if (accessToken) {
          applyAuthorization(accessToken)
          try { await fetchUser() }
          catch { if (refreshToken) { await refreshAccessToken(); await fetchUser() } else await logout() }
        } else clearAuthorization()
      } catch { await logout() }
      finally { if (active) { setLoading(false); setReady(true) } }
    }
    void bootstrap(); return () => { active = false }
  }, [])
  return ready ? children as React.ReactElement : null
}

export const initAuth = async () => {
  const { accessToken, refreshToken, fetchUser, refreshAccessToken, logout } = useAuthStore.getState()
  if (!accessToken) { clearAuthorization(); return }
  applyAuthorization(accessToken)
  try { await fetchUser() }
  catch { if (refreshToken) { try { await refreshAccessToken(); await fetchUser() } catch { await logout() } } else await logout() }
}
