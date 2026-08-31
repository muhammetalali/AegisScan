import axios, { AxiosError, AxiosRequestConfig, InternalAxiosRequestConfig } from 'axios'
import { useAuthStore } from '@/stores/authStore'

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1'

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
  xsrfCookieName: 'csrftoken',
  xsrfHeaderName: 'X-CSRFToken',
})

api.interceptors.request.use((config: InternalAxiosRequestConfig) => config, (error) => Promise.reject(error))

let isRefreshing = false
let failedQueue: Array<{ resolve: () => void; reject: (reason: unknown) => void }> = []

const processQueue = (error: Error | null) => {
  failedQueue.forEach(({ resolve, reject }) => error ? reject(error) : resolve())
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
      return new Promise<void>((resolve, reject) => failedQueue.push({ resolve, reject })).then(() => api(originalRequest))
    }

    isRefreshing = true
    try {
      await useAuthStore.getState().refreshAccessToken()
      processQueue(null)
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
  // Browser WebSockets must stay on the exact same origin as the SPA so the
  // HttpOnly JWT cookie is eligible for the handshake. Do not honor a
  // separately configured VITE_WS_URL here: it can silently switch localhost
  // to 127.0.0.1 and invalidate cookie-based authentication.
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const browserWs = `${wsProtocol}//${window.location.host}`
  const normalizedPath = url.startsWith('/') ? url : `/${url}`
  const wsUrl = `${browserWs}${normalizedPath}`
  const wsProtocols = protocols ? (Array.isArray(protocols) ? protocols : [protocols]) : []
  return new WebSocket(wsUrl, wsProtocols.length ? wsProtocols : undefined)
}

export default api
