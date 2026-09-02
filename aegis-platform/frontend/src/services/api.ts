import axios, { AxiosError, AxiosRequestConfig, InternalAxiosRequestConfig } from 'axios'
import { useAuthStore } from '@/stores/authStore'

const configuredApiUrl = String(import.meta.env.VITE_API_URL || '').trim().replace(/\/$/, '')
const API_BASE_URL = configuredApiUrl || (import.meta.env.DEV ? 'http://localhost:8000/api/v1' : '/api/v1')

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
  xsrfCookieName: 'csrftoken',
  xsrfHeaderName: 'X-CSRFToken',
})

api.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => config,
  (error) => Promise.reject(error),
)

let isRefreshing = false
let failedQueue: Array<{ resolve: (value: unknown) => void; reject: (reason: unknown) => void }> = []

const processQueue = (error: Error | null) => {
  failedQueue.forEach((prom) => error ? prom.reject(error) : prom.resolve(true))
  failedQueue = []
}

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean }
    const url = originalRequest?.url || ''
    const isAuthEndpoint = ['/auth/login/', '/auth/refresh/', '/auth/logout/', '/auth/csrf/'].some((path) => url.includes(path))

    if (error.response?.status === 401 && !originalRequest?._retry && !isAuthEndpoint) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => failedQueue.push({ resolve, reject }))
          .then(() => api(originalRequest))
      }

      originalRequest._retry = true
      isRefreshing = true
      try {
        await useAuthStore.getState().refreshAccessToken()
        processQueue(null)
        return api(originalRequest)
      } catch (refreshError) {
        processQueue(refreshError as Error)
        useAuthStore.setState({ user: null, isAuthenticated: false })
        return Promise.reject(refreshError)
      } finally {
        isRefreshing = false
      }
    }

    return Promise.reject(error)
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
    onUploadProgress: (event) => {
      if (event.total && onProgress) onProgress(Math.round((event.loaded * 100) / event.total))
    },
  })
  return response.data
}

export const createWebSocket = (url: string, protocols?: string | string[]) => {
  const configuredWsUrl = String(import.meta.env.VITE_WS_URL || '').trim().replace(/\/$/, '')
  const defaultWsUrl = import.meta.env.DEV
    ? 'ws://localhost:8000'
    : `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`
  const wsBaseUrl = configuredWsUrl || defaultWsUrl
  return new WebSocket(`${wsBaseUrl}${url}`, protocols)
}

export default api
