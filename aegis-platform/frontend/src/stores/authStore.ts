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

interface RegisterData {
  email: string
  password: string
  password_confirm: string
  first_name: string
  last_name: string
  phone?: string
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      loading: false,
      error: null,

      setLoading: (loading) => set({ loading }),
      setError: (error) => set({ error }),

      login: async (email, password, rememberMe = false) => {
        set({ loading: true, error: null })
        try {
          const response = await api.post('/auth/login/', { email, password })
          const { access, refresh, user } = response.data

          api.defaults.headers.common['Authorization'] = `Bearer ${access}`

          set({
            user,
            accessToken: access,
            refreshToken: refresh,
            isAuthenticated: true,
            loading: false,
          })
        } catch (error: any) {
          set({ loading: false, error: error.response?.data?.detail || 'Login failed' })
          throw error
        }
      },

      register: async (data) => {
        set({ loading: true, error: null })
        try {
          const response = await api.post('/auth/register/', data)
          const { access, refresh, user } = response.data

          api.defaults.headers.common['Authorization'] = `Bearer ${access}`

          set({
            user,
            accessToken: access,
            refreshToken: refresh,
            isAuthenticated: true,
            loading: false,
          })
        } catch (error: any) {
          set({ loading: false, error: error.response?.data?.detail || 'Registration failed' })
          throw error
        }
      },

      logout: async () => {
        const { refreshToken } = get()
        try {
          if (refreshToken) {
            await api.post('/auth/logout/', { refresh_token: refreshToken })
          }
        } catch {
          // Ignore logout errors
        } finally {
          delete api.defaults.headers.common['Authorization']
          set({
            user: null,
            accessToken: null,
            refreshToken: null,
            isAuthenticated: false,
          })
        }
      },

      refreshAccessToken: async () => {
        const { refreshToken } = get()
        if (!refreshToken) return

        try {
          const response = await api.post('/auth/refresh/', { refresh: refreshToken })
          const { access } = response.data

          api.defaults.headers.common['Authorization'] = `Bearer ${access}`
          set({ accessToken: access })
        } catch {
          get().logout()
        }
      },

      forgotPassword: async (email) => {
        set({ loading: true, error: null })
        try {
          await api.post('/auth/password/reset/', { email })
          set({ loading: false })
        } catch (error: any) {
          set({ loading: false, error: error.response?.data?.detail || 'Failed to send reset email' })
          throw error
        }
      },

      resetPassword: async (token, password) => {
        set({ loading: true, error: null })
        try {
          await api.post('/auth/password/reset/confirm/', { token, password })
          set({ loading: false })
        } catch (error: any) {
          set({ loading: false, error: error.response?.data?.detail || 'Failed to reset password' })
          throw error
        }
      },

      verifyEmail: async (token) => {
        set({ loading: true, error: null })
        try {
          await api.post('/auth/verify-email/', { token })
          set({ loading: false })
        } catch (error: any) {
          set({ loading: false, error: error.response?.data?.detail || 'Failed to verify email' })
          throw error
        }
      },

      updateProfile: async (data) => {
        set({ loading: true, error: null })
        try {
          const response = await api.patch('/users/me/', data)
          set({ user: response.data, loading: false })
        } catch (error: any) {
          set({ loading: false, error: error.response?.data?.detail || 'Failed to update profile' })
          throw error
        }
      },

      changePassword: async (oldPassword, newPassword) => {
        set({ loading: true, error: null })
        try {
          await api.post('/users/me/change_password/', { old_password: oldPassword, new_password: newPassword })
          set({ loading: false })
        } catch (error: any) {
          set({ loading: false, error: error.response?.data?.detail || 'Failed to change password' })
          throw error
        }
      },

      enable2FA: async () => {
        const response = await api.post('/users/me/2fa/enable/')
        return response.data
      },

      verify2FA: async (code) => {
        await api.post('/users/me/2fa/verify/', { code })
      },

      disable2FA: async () => {
        await api.post('/users/me/2fa/disable/')
      },

      fetchUser: async () => {
        try {
          const response = await api.get('/users/me/')
          set({ user: response.data })
        } catch {
          // Token might be expired
        }
      },
    }),
    {
      name: 'aegis-auth',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
)

// React compatible hooks / provider
import React from 'react'
export const useAuth = () => {
  const store = useAuthStore()
  return store
}
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return children as React.ReactElement
}

// Initialize auth on app load
export const initAuth = async () => {
  const { accessToken, refreshToken, fetchUser, refreshAccessToken, logout } = useAuthStore.getState()

  if (accessToken) {
    api.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`
    try {
      await fetchUser()
    } catch {
      if (refreshToken) {
        try {
          await refreshAccessToken()
          await fetchUser()
        } catch {
          logout()
        }
      } else {
        logout()
      }
    }
  }
}