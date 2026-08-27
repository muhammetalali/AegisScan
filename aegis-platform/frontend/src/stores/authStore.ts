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
  login: (email: string, password: string, rememberMe?: boolean) => Promise<void>
  register: (data: RegisterData) => Promise<void>
  logout: () => Promise<void>
  refreshAccessToken: () => Promise<void>
  forgotPassword: (email: string) => Promise<void>
  resetPassword: (token: string, password: string) => Promise<void>
  verifyEmail: (token: string) => Promise<void>
  updateProfile: (data: Partial<User>) => Promise<void>
  changePassword: (oldPassword: string, newPassword: string) => Promise<void>
  enable2FA: () => Promise<{ secret: string; qrCode: string }>
  verify2FA: (code: string) => Promise<void>
  disable2FA: () => Promise<void>
  fetchUser: () => Promise<void>
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
}

interface RegisterData { email: string; password: string; password_confirm: string; first_name: string; last_name: string; phone?: string }

export const useAuthStore = create<AuthState>()(persist((set, get) => ({
  user: null, accessToken: null, refreshToken: null, isAuthenticated: false, loading: false, error: null,
  setLoading: (loading) => set({ loading }), setError: (error) => set({ error }),
  login: async (email, password) => {
    set({ loading: true, error: null })
    try {
      const { data } = await api.post('/auth/login/', { email, password })
      if (!data?.access || !data?.refresh || !data?.user) throw new Error('Invalid login response')
      api.defaults.headers.common['Authorization'] = `Bearer ${data.access}`
      set({ user: data.user, accessToken: data.access, refreshToken: data.refresh, isAuthenticated: true, loading: false })
    } catch (error: any) {
      set({ loading: false, isAuthenticated: false, error: error.response?.data?.detail || error.message || 'Login failed' })
      throw error
    }
  },
  register: async (data) => {
    set({ loading: true, error: null })
    try {
      const { data: response } = await api.post('/auth/register/', data)
      if (!response?.access || !response?.refresh || !response?.user) throw new Error('Invalid registration response')
      api.defaults.headers.common['Authorization'] = `Bearer ${response.access}`
      set({ user: response.user, accessToken: response.access, refreshToken: response.refresh, isAuthenticated: true, loading: false })
    } catch (error: any) {
      set({ loading: false, isAuthenticated: false, error: error.response?.data?.detail || error.message || 'Registration failed' })
      throw error
    }
  },
  logout: async () => {
    const { refreshToken } = get()
    try { if (refreshToken) await api.post('/auth/logout/', { refresh_token: refreshToken }) } catch { /* local cleanup below */ }
    delete api.defaults.headers.common['Authorization']
    set({ user: null, accessToken: null, refreshToken: null, isAuthenticated: false, loading: false, error: null })
  },
  refreshAccessToken: async () => {
    const { refreshToken } = get()
    if (!refreshToken) throw new Error('No refresh token available')
    try {
      const { data } = await api.post('/auth/refresh/', { refresh: refreshToken })
      if (!data?.access) throw new Error('Invalid refresh response')
      api.defaults.headers.common['Authorization'] = `Bearer ${data.access}`
      set({ accessToken: data.access, isAuthenticated: true, error: null })
    } catch (error) {
      delete api.defaults.headers.common['Authorization']
      set({ user: null, accessToken: null, refreshToken: null, isAuthenticated: false })
      throw error
    }
  },
  forgotPassword: async (email) => { set({ loading: true, error: null }); try { await api.post('/auth/password/reset/', { email }); set({ loading: false }) } catch (error: any) { set({ loading: false, error: error.response?.data?.detail || error.message || 'Failed to send reset email' }); throw error } },
  resetPassword: async (token, password) => { set({ loading: true, error: null }); try { await api.post('/auth/password/reset/confirm/', { token, password }); set({ loading: false }) } catch (error: any) { set({ loading: false, error: error.response?.data?.detail || error.message || 'Failed to reset password' }); throw error } },
  verifyEmail: async (token) => { set({ loading: true, error: null }); try { await api.post('/auth/verify-email/', { token }); set({ loading: false }) } catch (error: any) { set({ loading: false, error: error.response?.data?.detail || error.message || 'Failed to verify email' }); throw error } },
  updateProfile: async (data) => { set({ loading: true, error: null }); try { const response = await api.patch('/users/me/', data); set({ user: response.data, loading: false }) } catch (error: any) { set({ loading: false, error: error.response?.data?.detail || error.message || 'Failed to update profile' }); throw error } },
  changePassword: async (oldPassword, newPassword) => { set({ loading: true, error: null }); try { await api.post('/users/me/change_password/', { old_password: oldPassword, new_password: newPassword }); set({ loading: false }) } catch (error: any) { set({ loading: false, error: error.response?.data?.detail || error.message || 'Failed to change password' }); throw error } },
  enable2FA: async () => (await api.post('/users/me/2fa/enable/')).data,
  verify2FA: async (code) => { await api.post('/users/me/2fa/verify/', { code }) },
  disable2FA: async () => { await api.post('/users/me/2fa/disable/') },
  fetchUser: async () => { const response = await api.get('/users/me/'); if (!response.data) throw new Error('Invalid user response'); set({ user: response.data, isAuthenticated: true, error: null }) },
}), { name: 'aegis-auth', storage: createJSONStorage(() => localStorage), partialize: (state) => ({ accessToken: state.accessToken, refreshToken: state.refreshToken, user: state.user, isAuthenticated: state.isAuthenticated }) }))

export const useAuth = () => useAuthStore()

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [ready, setReady] = useState(false)
  const { accessToken, refreshToken, fetchUser, refreshAccessToken, logout, setLoading } = useAuthStore()
  useEffect(() => {
    let active = true
    const bootstrap = async () => {
      setLoading(true)
      try {
        if (accessToken) {
          api.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`
          try { await fetchUser() } catch { if (refreshToken) { await refreshAccessToken(); await fetchUser() } else await logout() }
        }
      } catch { await logout() }
      finally { if (active) { setLoading(false); setReady(true) } }
    }
    void bootstrap()
    return () => { active = false }
  }, [])
  return ready ? children as React.ReactElement : null
}

export const initAuth = async () => {
  const { accessToken, refreshToken, fetchUser, refreshAccessToken, logout } = useAuthStore.getState()
  if (!accessToken) return
  api.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`
  try { await fetchUser() } catch { if (refreshToken) { try { await refreshAccessToken(); await fetchUser() } catch { await logout() } } else await logout() }
}
