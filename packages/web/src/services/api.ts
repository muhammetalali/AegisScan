import axios, { AxiosError, AxiosRequestConfig, InternalAxiosRequestConfig } from 'axios'
import { useAuthStore } from '@/stores/authStore'

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1'

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
})

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const { accessToken } = useAuthStore.getState()
  if (accessToken && config.headers) config.headers.Authorization = `Bearer ${accessToken}`
  return config
}, (error) => Promise.reject(error))

let isRefreshing = false
let failedQueue: Array<{ resolve: (value: unknown) => void; reject: (reason: unknown) => void }> = []

const processQueue = (error: Error | null, token: string | null = null) => {
  failedQueue.forEach(({ resolve, reject }) => error ? reject(error) : resolve(token))
  failedQueue = []
}

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as (InternalAxiosRequestConfig & { _retry?: boolean }) | undefined
    const url = originalRequest?.url || ''
    const isRefreshRequest = url.includes('/auth/refresh/')
    const isAuthRequest = url.includes('/auth/login/') || url.includes('/auth/register/')
    const isLogoutRequest = url.includes('/users/logout/')

    if (error.response?.status !== 401 || !originalRequest || originalRequest._retry || isRefreshRequest || isAuthRequest || isLogoutRequest) {
      return Promise.reject(error)
    }

    originalRequest._retry = true

    if (isRefreshing) {
      return new Promise((resolve, reject) => failedQueue.push({ resolve, reject })).then((token) => {
        if (!token || !originalRequest.headers) return Promise.reject(error)
        originalRequest.headers.Authorization = `Bearer ${String(token)}`
        return api(originalRequest)
      })
    }

    isRefreshing = true
    try {
      const { refreshToken, refreshAccessToken } = useAuthStore.getState()
      if (!refreshToken) throw new Error('Session expired')
      await refreshAccessToken()
      const { accessToken } = useAuthStore.getState()
      if (!accessToken) throw new Error('Session refresh failed')
      processQueue(null, accessToken)
      if (originalRequest.headers) originalRequest.headers.Authorization = `Bearer ${accessToken}`
      return api(originalRequest)
    } catch (refreshError) {
      const reason = refreshError instanceof Error ? refreshError : new Error('Session expired')
      processQueue(reason)
      await useAuthStore.getState().logout()
      if (window.location.pathname !== '/login') window.location.assign('/login')
      return Promise.reject(refreshError)
    } finally {
      isRefreshing = false
    }
  },
)

export const apiHelpers = {
  get: <T>(url: string, config?: AxiosRequestConfig) => api.get<T>(url, config).then((r) => r.data),
  post: <T>(url: string, data?: unknown, config?: AxiosRequestConfig) => api.post<T>(url, data, config).then((r) => r.data),
  put: <T>(url: string, data?: unknown, config?: AxiosRequestConfig) => api.put<T>(url, data, config).then((r) => r.data),
  patch: <T>(url: string, data?: unknown, config?: AxiosRequestConfig) => api.patch<T>(url, data, config).then((r) => r.data),
  delete: <T>(url: string, config?: AxiosRequestConfig) => api.delete<T>(url, config).then((r) => r.data),
}

export const uploadFile = async (file: File, onProgress?: (progress: number) => void) => {
  const formData = new FormData()
  formData.append('file', file)
  const response = await api.post('/uploads/', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (progressEvent) => {
      if (progressEvent.total && onProgress) onProgress(Math.round((progressEvent.loaded * 100) / progressEvent.total))
    },
  })
  return response.data
}

export const createWebSocket = (url: string, protocols?: string | string[]) => {
  const { accessToken } = useAuthStore.getState()
  const browserWs = import.meta.env.VITE_WS_URL || `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`
  const wsUrl = `${browserWs}${url}${accessToken ? `?token=${encodeURIComponent(accessToken)}` : ''}`
  return new WebSocket(wsUrl, protocols)
}

export default api
