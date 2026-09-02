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

const readError = (error: any, fallback: string) => {
  const detail = error?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (detail?.message) return detail.message
  if (error?.response?.data?.error?.message) return error.response.data.error.message
  return fallback
}

const ME_ENDPOINT = '/auth/users/me/'
const CHANGE_PASSWORD_ENDPOINT = '/auth/users/me/change_password/'
const TWO_FA_ENABLE_ENDPOINT = '/auth/users/me/2fa/enable/'
const TWO_FA_VERIFY_ENDPOINT = '/auth/users/me/2fa/verify/'
const TWO_FA_DISABLE_ENDPOINT = '/auth/users/me/2fa/disable/'

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
      await api.get('/auth/csrf/')
      const response = await api.post('/auth/login/', { email, password })
      set({ user: response.data.user, isAuthenticated: true, loading: false, error: null })
    } catch (error: any) {
      const message = readError(error, 'تعذر تسجيل الدخول')
      set({ loading: false, error: message })
      throw error
    }
  },

  register: async (data) => {
    set({ loading: true, error: null })
    try {
      await api.get('/auth/csrf/')
      await api.post('/auth/register/', data)
      await get().login(data.email, data.password)
      set({ loading: false })
    } catch (error: any) {
      set({ loading: false, error: readError(error, 'تعذر إنشاء الحساب') })
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
      set({ loading: false, error: readError(error, 'تعذر إرسال رسالة إعادة التعيين') })
      throw error
    }
  },

  resetPassword: async (token, password) => {
    set({ loading: true, error: null })
    try {
      await api.post('/auth/password/reset/confirm/', { token, password })
      set({ loading: false })
    } catch (error: any) {
      set({ loading: false, error: readError(error, 'تعذر إعادة تعيين كلمة المرور') })
      throw error
    }
  },

  verifyEmail: async (token) => {
    set({ loading: true, error: null })
    try {
      await api.post('/auth/verify-email/', { token })
      set({ loading: false })
    } catch (error: any) {
      set({ loading: false, error: readError(error, 'تعذر التحقق من البريد الإلكتروني') })
      throw error
    }
  },

  updateProfile: async (data) => {
    set({ loading: true, error: null })
    try {
      const response = await api.patch(ME_ENDPOINT, data)
      set({ user: response.data, loading: false })
    } catch (error: any) {
      set({ loading: false, error: readError(error, 'تعذر تحديث الملف الشخصي') })
      throw error
    }
  },

  changePassword: async (oldPassword, newPassword) => {
    set({ loading: true, error: null })
    try {
      await api.post(CHANGE_PASSWORD_ENDPOINT, { old_password: oldPassword, new_password: newPassword })
      set({ loading: false })
    } catch (error: any) {
      set({ loading: false, error: readError(error, 'تعذر تغيير كلمة المرور') })
      throw error
    }
  },

  enable2FA: async () => (await api.post(TWO_FA_ENABLE_ENDPOINT)).data,
  verify2FA: async (code) => { await api.post(TWO_FA_VERIFY_ENDPOINT, { code }) },
  disable2FA: async () => { await api.post(TWO_FA_DISABLE_ENDPOINT) },

  fetchUser: async () => {
    const response = await api.get(ME_ENDPOINT)
    set({ user: response.data, isAuthenticated: true, error: null })
  },
}))

import React from 'react'
export const useAuth = () => useAuthStore()
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => children as React.ReactElement

export const initAuth = async () => {
  const store = useAuthStore.getState()
  store.setLoading(true)
  store.setError(null)
  try {
    await api.get('/auth/csrf/')
    await store.fetchUser()
  } catch {
    try {
      await store.refreshAccessToken()
      await store.fetchUser()
    } catch {
      useAuthStore.setState({ user: null, isAuthenticated: false, error: null })
    }
  } finally {
    useAuthStore.setState({ loading: false })
  }
}
