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
  const configuredWs = String(import.meta.env.VITE_WS_URL || '').trim()
  let browserWs = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`

  // Same-origin WebSockets keep the HttpOnly auth cookie attached to the
  // connection. In local development this also prevents localhost/127.0.0.1
  // cookie-domain mismatches.
  if (configuredWs) {
    try {
      const parsed = new URL(configuredWs)
      const configuredHost = parsed.hostname.toLowerCase()
      const browserHost = window.location.hostname.toLowerCase()
      const loopbackHosts = new Set(['localhost', '127.0.0.1', '[::1]', '::1'])
      if (loopbackHosts.has(configuredHost) || loopbackHosts.has(browserHost)) {
        parsed.hostname = window.location.hostname
        parsed.port = window.location.port || parsed.port
      }
      browserWs = `${parsed.protocol}//${parsed.host}`
    } catch {
      browserWs = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`
    }
  }

  const normalizedPath = url.startsWith('/') ? url : `/${url}`
  const wsUrl = `${browserWs}${normalizedPath}`
  const wsProtocols = protocols ? (Array.isArray(protocols) ? protocols : [protocols]) : []
  return new WebSocket(wsUrl, wsProtocols.length ? wsProtocols : undefined)
}

export default api
