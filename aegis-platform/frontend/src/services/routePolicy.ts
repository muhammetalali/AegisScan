import type { UserRole } from '@/types'
import { NAV_GROUPS } from '@/components/layout/navigation'

// A single client-side navigation contract; backend permission checks remain authoritative.
const EDITOR_ROLES: UserRole[] = ['security_analyst', 'security_manager', 'admin', 'super_admin']

// The backend user endpoint returns effective permissions, already intersected
// with the owner's per-user grants. Role-only checks are a compatibility fallback
// for purely static route tests; authenticated navigation always supplies grants.
const PAGE_PERMISSIONS: Record<string, string> = {
  '/projects':'project.read', '/assets':'asset.read',
  '/assess':'scan.create', '/scan':'scan.read', '/web-labs':'scan.create',
  '/validations':'scan.read', '/vulnerabilities':'vulnerability.read',
  '/evidence':'scan.read', '/reports':'report.read',
  '/compliance':'compliance.read', '/assurance':'scan.read',
  '/wstg':'scan.read', '/posture':'scan.read',
  '/digital-twin':'digital_twin.read', '/knowledge':'knowledge.read',
  '/security-events':'security_event.read', '/users':'user.read',
  '/keys':'api_key.manage', '/audit':'audit.read',
  '/settings':'system.settings', '/system':'system.monitor',
}

export const canAccessRoute = (path: string, role?: UserRole | null, permissions?: string[] | null, enabledPages?: string[] | null, isCompanyOwner = false): boolean => {
  if (!role) return false
  // Only the server-verified primary company owner bypasses employee UI page grants.
  if (isCompanyOwner) return true
  if (/^\/projects\/[^/]+\/assess(?:\/|$)/.test(path) || path === '/validations/new' || path.startsWith('/validations/')) {
    const isReadOnly = path.includes('/progress') || path.includes('/results')
    const grant = isReadOnly ? 'scan.read' : 'scan.create'
    const requiredPage = isReadOnly ? '/scan' : '/assess'
    return EDITOR_ROLES.includes(role) && (permissions == null || permissions.includes(grant))
      && (enabledPages == null || enabledPages.includes(requiredPage))
  }
  const matching = NAV_GROUPS.flatMap(group => group.items)
    .filter(item => path === item.href || path.startsWith(item.href + '/'))
    .sort((a, b) => b.href.length - a.href.length)[0]
  const roleAllowed = !matching || matching.roles.includes('all') || matching.roles.includes(role)
  if (!roleAllowed) return false
  // Effective permissions never enlarge the configured UI page allowlist.
  if (enabledPages != null && path !== '/' && path !== '/dashboard') {
    const page = matching?.href
    if (!page || !enabledPages.includes(page)) return false
  }
  if (permissions !== undefined && permissions !== null) {
    const entry = Object.entries(PAGE_PERMISSIONS)
      .filter(([prefix]) => path === prefix || path.startsWith(prefix + '/'))
      .sort((a,b)=>b[0].length-a[0].length)[0]
    if (entry && !permissions.includes(entry[1])) return false
  }
  return true
}

export const canManageKeys = (role?: UserRole | null): boolean =>
  role === 'super_admin' || role === 'admin' || role === 'security_manager'
