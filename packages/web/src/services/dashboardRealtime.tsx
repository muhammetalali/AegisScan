import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { createWebSocket } from './api'
import { useAuth } from '@/stores/authStore'

type DashboardSnapshot = {
  summary: unknown
  risk_distribution: unknown
  trends: unknown
  recent_validations: unknown
}

export function DashboardRealtime() {
  const queryClient = useQueryClient()
  const { isAuthenticated } = useAuth()

  useEffect(() => {
    if (!isAuthenticated) return

    let socket: WebSocket | null = null
    let reconnectTimer: number | undefined
    let disposed = false
    let reconnectDelay = 1000

    const connect = () => {
      if (disposed) return
      socket = createWebSocket('/ws/dashboard/')
      socket.onopen = () => { reconnectDelay = 1000 }
      socket.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data) as { type?: string; data?: DashboardSnapshot }
          if (message.type !== 'dashboard_snapshot' || !message.data) return
          queryClient.setQueryData(['dash-summary'], message.data.summary)
          queryClient.setQueryData(['dash-risk'], message.data.risk_distribution)
          queryClient.setQueryData(['dash-trends'], message.data.trends)
          queryClient.setQueryData(['dash-recent'], message.data.recent_validations)
        } catch {
          // Ignore malformed frames; the HTTP queries remain the source of truth.
        }
      }
      socket.onclose = () => {
        if (disposed) return
        reconnectTimer = window.setTimeout(connect, reconnectDelay)
        reconnectDelay = Math.min(reconnectDelay * 2, 30000)
      }
      socket.onerror = () => socket?.close()
    }

    connect()
    return () => {
      disposed = true
      if (reconnectTimer) window.clearTimeout(reconnectTimer)
      socket?.close()
    }
  }, [isAuthenticated, queryClient])

  return null
}
