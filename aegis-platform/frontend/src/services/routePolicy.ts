import type { UserRole } from '@/types'
import { NAV_GROUPS } from '@/components/layout/navigation'

// A single client-side navigation contract; backend permission checks remain authoritative.
const EDITOR_ROLES: UserRole[] = ['security_analyst', 'security_manager', 'admin', 'super_admin']

export const canAccessRoute = (path: string, role?: UserRole | null): boolean => {
  if (!role) return false
  if (/^\/projects\/[^/]+\/assess(?:\/|$)/.test(path) || path === '/validations/new' || path.startsWith('/validations/')) {
    return EDITOR_ROLES.includes(role)
  }
  const matching = NAV_GROUPS.flatMap(group => group.items)
    .filter(item => path === item.href || path.startsWith(item.href + '/'))
    .sort((a, b) => b.href.length - a.href.length)[0]
  return !matching || matching.roles.includes('all') || matching.roles.includes(role)
}

export const canManageKeys = (role?: UserRole | null): boolean =>
  role === 'super_admin' || role === 'admin' || role === 'security_manager'
