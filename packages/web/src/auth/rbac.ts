import type { User, UserRole } from '@/types'

export type AccessRequirement = {
  roles?: UserRole[]
  permissions?: string[]
  mode?: 'any' | 'all'
}

const rolePermissions: Record<UserRole, string[]> = {
  super_admin: ['*'],
  admin: ['platform:admin', 'users:read', 'users:write', 'security:read', 'security:write', 'reports:read', 'settings:write', 'audit:read'],
  security_manager: ['security:read', 'security:write', 'projects:read', 'projects:write', 'assets:read', 'assets:write', 'reports:read', 'audit:read'],
  security_analyst: ['security:read', 'projects:read', 'assets:read', 'validations:read', 'validations:write', 'vulnerabilities:read', 'vulnerabilities:write', 'reports:read', 'assurance:read'],
  developer: ['security:read', 'projects:read', 'projects:write', 'assets:read', 'assets:write', 'validations:read', 'validations:write', 'vulnerabilities:read'],
  auditor: ['security:read', 'projects:read', 'assets:read', 'vulnerabilities:read', 'reports:read', 'compliance:read', 'audit:read', 'assurance:read'],
  viewer: ['security:read', 'projects:read', 'assets:read', 'vulnerabilities:read', 'reports:read', 'compliance:read', 'assurance:read'],
}

export const hasPermission = (user: User | null, permission: string): boolean => {
  if (!user || !user.is_active) return false
  const explicit = user.permissions ?? []
  if (explicit.includes('*') || explicit.includes(permission)) return true
  return (rolePermissions[user.role] ?? []).some((item) => item === '*' || item === permission)
}

export const canAccess = (user: User | null, requirement?: AccessRequirement): boolean => {
  if (!requirement) return Boolean(user?.is_active)
  if (!user?.is_active) return false

  const mode = requirement.mode ?? 'any'
  const roleAllowed = requirement.roles?.length
    ? mode === 'all'
      ? requirement.roles.every((role) => user.role === role)
      : requirement.roles.includes(user.role)
    : true
  const permissionAllowed = requirement.permissions?.length
    ? mode === 'all'
      ? requirement.permissions.every((permission) => hasPermission(user, permission))
      : requirement.permissions.some((permission) => hasPermission(user, permission))
    : true

  return mode === 'all' ? roleAllowed && permissionAllowed : roleAllowed && permissionAllowed
}

export const routeAccess: Record<string, AccessRequirement> = {
  '/users': { roles: ['super_admin', 'admin'] },
  '/audit': { permissions: ['audit:read'] },
  '/system': { roles: ['super_admin', 'admin'] },
  '/settings': { roles: ['super_admin', 'admin', 'security_manager', 'developer'] },
  '/reports': { permissions: ['reports:read'] },
  '/compliance': { permissions: ['compliance:read'] },
  '/compliance/intelligence': { permissions: ['compliance:read'] },
  '/assurance': { permissions: ['assurance:read'] },
  '/assurance/continuous': { permissions: ['assurance:read'] },
  '/assurance/conflicts': { permissions: ['assurance:read'] },
  '/assurance/evidence': { permissions: ['assurance:read'] },
  '/assurance/graph': { permissions: ['assurance:read'] },
  '/assurance/triage': { roles: ['super_admin', 'admin', 'security_manager', 'security_analyst'] },
  '/assurance/decisions': { roles: ['super_admin', 'admin', 'security_manager', 'security_analyst'] },
  '/assurance/actions': { roles: ['super_admin', 'admin', 'security_manager', 'security_analyst'] },
  '/assurance/workflow': { roles: ['super_admin', 'admin', 'security_manager'] },
  '/assurance/governance': { roles: ['super_admin', 'admin', 'security_manager', 'auditor'] },
  '/assurance/policies': { roles: ['super_admin', 'admin', 'security_manager'] },
  '/assurance/policies/simulate': { roles: ['super_admin', 'admin', 'security_manager'] },
  '/executive': { roles: ['super_admin', 'admin', 'security_manager', 'auditor'] },
}

export const getRouteAccess = (pathname: string): AccessRequirement | undefined => {
  const exact = routeAccess[pathname]
  if (exact) return exact
  const prefix = Object.keys(routeAccess).find((route) => pathname.startsWith(`${route}/`))
  return prefix ? routeAccess[prefix] : undefined
}
