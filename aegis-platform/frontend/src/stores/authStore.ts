import { create } from 'zustand'
import { api } from '@/services/api'
import type { User } from '@/types'

const SESSION_HINT_KEY = 'aegis-session-active'
const hasSessionHint = () => typeof window !== 'undefined' && window.localStorage.getItem(SESSION_HINT_KEY) === '1'
const setSessionHint = (active: boolean) => {
  if (typeof window === 'undefined') return
  if (active) window.localStorage.setItem(SESSION_HINT_KEY, '1')
  else window.localStorage.removeItem(SESSION_HINT_KEY)
}

interface AuthState {
  user: User | null
  accessToken: null
  refreshToken: null
  isAuthenticated: boolean
  loading: boolean
  initialized: boolean
  error: string | null
  login: (email: string, password: string, rememberMe?: boolean) => Promise<void>
  logout: () => Promise<void>
  refreshAccessToken: () => Promise<void>
  fetchUser: () => Promise<void>
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
}

const readError = (error: any, fallback: string) => {
  const detail = error?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (detail?.message) return detail.message
  if (error?.response?.data?.error?.message) return error.response.data.error.message
  return fallback
}

const ME_ENDPOINT = '/auth/users/me/'
export const useAuthStore = create<AuthState>()((set, get) => ({
  user: null,
  accessToken: null,
  refreshToken: null,
  isAuthenticated: hasSessionHint(),
  loading: true,
  initialized: false,
  error: null,

  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),

  login: async (email, password) => {
    set({ loading: true, error: null })
    try {
      await api.get('/auth/csrf/')
      const response = await api.post('/auth/login/', { email, password })
      setSessionHint(true)
      set({ user: response.data.user, isAuthenticated: true, loading: false, initialized: true, error: null })
    } catch (error: any) {
      const message = readError(error, 'تعذر تسجيل الدخول')
      set({ loading: false, error: message, initialized: true })
      throw error
    }
  },

  logout: async () => {
    try {
      await api.post('/auth/logout/')
    } finally {
      setSessionHint(false)
      set({ user: null, isAuthenticated: false, loading: false, initialized: true, error: null })
    }
  },

  refreshAccessToken: async () => {
    await api.post('/auth/refresh/')
    setSessionHint(true)
  },

  fetchUser: async () => {
    const response = await api.get(ME_ENDPOINT)
    setSessionHint(true)
    set({ user: response.data, isAuthenticated: true, error: null })
  },
}))

import React from 'react'
export const useAuth = () => useAuthStore()
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => children as React.ReactElement

let initializationPromise: Promise<void> | null = null

export const initAuth = async () => {
  if (initializationPromise) return initializationPromise

  initializationPromise = (async () => {
    const store = useAuthStore.getState()
    store.setLoading(true)
    store.setError(null)
    try {
      await api.get('/auth/csrf/')
      await store.fetchUser()
    } catch (firstError: any) {
      if (firstError?.response?.status === 401) {
        try {
          await store.refreshAccessToken()
          await store.fetchUser()
        } catch (refreshError: any) {
          if (refreshError?.response?.status === 401) {
            setSessionHint(false)
            useAuthStore.setState({ user: null, isAuthenticated: false, error: null })
          }
        }
      } else if (hasSessionHint()) {
        // Preserve the session across a transient network/reverse-proxy failure.
        // The next authenticated API request remains authoritative and can clear the hint on a real 401.
        useAuthStore.setState({ isAuthenticated: true })
      }
    } finally {
      useAuthStore.setState({ loading: false, initialized: true })
    }
  })()

  try {
    await initializationPromise
  } finally {
    initializationPromise = null
  }
}
