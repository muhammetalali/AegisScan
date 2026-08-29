import { create } from 'zustand'
import { api } from '@/services/api'
import type { User } from '@/types'

interface AuthState {
  user: User | null
  accessToken: null
  refreshToken: null
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

export const useAuthStore = create<AuthState>()((set, get) => ({
  user: null,
  accessToken: null,
  refreshToken: null,
  isAuthenticated: false,
  loading: false,
  error: null,

  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),

  login: async (email, password) => {
    set({ loading: true, error: null })
    try {
      const response = await api.post('/auth/login/', { email, password })
      set({ user: response.data.user, isAuthenticated: true, loading: false })
    } catch (error: any) {
      set({ loading: false, error: error.response?.data?.detail || 'Login failed' })
      throw error
    }
  },

  register: async (data) => {
    set({ loading: true, error: null })
    try {
      await api.post('/auth/register/', data)
      await get().login(data.email, data.password)
      set({ loading: false })
    } catch (error: any) {
      set({ loading: false, error: error.response?.data?.detail || 'Registration failed' })
      throw error
    }
  },

  logout: async () => {
    try {
      await api.post('/auth/logout/')
    } finally {
      set({ user: null, isAuthenticated: false, loading: false, error: null })
    }
  },

  refreshAccessToken: async () => {
    await api.post('/auth/refresh/')
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

  enable2FA: async () => (await api.post('/users/me/2fa/enable/')).data,
  verify2FA: async (code) => { await api.post('/users/me/2fa/verify/', { code }) },
  disable2FA: async () => { await api.post('/users/me/2fa/disable/') },

  fetchUser: async () => {
    const response = await api.get('/users/me/')
    set({ user: response.data, isAuthenticated: true })
  },
}))

import React from 'react'
export const useAuth = () => useAuthStore()
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => children as React.ReactElement

export const initAuth = async () => {
  try {
    await api.get('/auth/csrf/')
    await useAuthStore.getState().fetchUser()
  } catch {
    try {
      await useAuthStore.getState().refreshAccessToken()
      await useAuthStore.getState().fetchUser()
    } catch {
      useAuthStore.setState({ user: null, isAuthenticated: false })
    }
  }
}
