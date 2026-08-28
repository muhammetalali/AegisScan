import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '@/stores/authStore'
import { canAccess, getRouteAccess } from '@/auth/rbac'
import { LoadingScreen } from '@/components/ui/LoadingScreen'

export const RouteGuard = ({ children }: { children: ReactNode }) => {
  const location = useLocation()
  const { user, isAuthenticated, loading } = useAuth()

  if (loading) return <LoadingScreen />
  if (!isAuthenticated || !user) return <Navigate to="/login" replace state={{ from: location.pathname }} />

  const requirement = getRouteAccess(location.pathname)
  if (!canAccess(user, requirement)) {
    return <Navigate to="/dashboard" replace state={{ deniedPath: location.pathname }} />
  }

  return <>{children}</>
}
