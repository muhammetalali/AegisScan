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
    let reconnectAttempts = 0
    const MAX_RECONNECT_ATTEMPTS = 5

    const connect = () => {
      if (disposed) return
      socket = createWebSocket('/ws/dashboard/')
      socket.onopen = () => {
        reconnectDelay = 1000
        reconnectAttempts = 0
      }
      socket.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data) as { type?: string; data?: DashboardSnapshot } & Partial<DashboardSnapshot>
          const snapshot = message.type === 'dashboard.snapshot' ? {
            summary: message.summary,
            risk_distribution: message.risk_distribution,
            trends: message.trends,
            recent_validations: message.recent_validations,
          } : message.type === 'dashboard_snapshot' ? message.data : undefined
          if (!snapshot) return
          queryClient.setQueryData(['dash-summary'], snapshot.summary)
          queryClient.setQueryData(['dash-risk'], snapshot.risk_distribution)
          queryClient.setQueryData(['dash-trends'], snapshot.trends)
          queryClient.setQueryData(['dash-recent'], snapshot.recent_validations)
        } catch {
          // HTTP dashboard queries remain the source of truth if a frame is invalid.
        }
      }
      socket.onclose = (event) => {
        if (disposed) return
        // 4001/4003 are explicit authentication/authorization failures.
        // Retrying those connections only creates a console-spam loop.
        if (event.code === 4001 || event.code === 4003) return
        if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) return
        reconnectAttempts += 1
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
