import { useMemo, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { CommandPalette } from './CommandPalette'
import { useAuthStore } from '@/stores/authStore'
import { hasPermission } from '@/auth/rbac'
import { LayoutDashboard, FolderKanban, Server, Zap, Activity, Bug, FileText, ShieldCheck, BookOpen, GitBranch, TrendingUp, Users, Settings, Monitor, ClipboardList, Bell, Gauge } from 'lucide-react'
import type { UserRole } from '@/types'

type NavItem = { name: string; href: string; icon: typeof LayoutDashboard; roles: Array<'all' | UserRole>; permission?: string }

export const NAV_GROUPS: Array<{ label: string; items: NavItem[] }> = [
  { label: 'Overview', items: [{ name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard, roles: ['all'] }] },
  { label: 'Workspace', items: [
    { name: 'Projects', href: '/projects', icon: FolderKanban, roles: ['all'] },
    { name: 'Assets', href: '/assets', icon: Server, roles: ['all'] },
  ] },
  { label: 'Validate', items: [
    { name: 'New Validation', href: '/validations/new', icon: Zap, roles: ['super_admin', 'admin', 'security_manager', 'security_analyst', 'developer'] },
    { name: 'Validations', href: '/scan', icon: Activity, roles: ['all'] },
    { name: 'Findings', href: '/vulnerabilities', icon: Bug, roles: ['all'] },
  ] },
  { label: 'Analyze', items: [
    { name: 'Reports', href: '/reports', icon: FileText, roles: ['all'], permission: 'reports:read' },
    { name: 'Compliance', href: '/compliance', icon: ShieldCheck, roles: ['all'], permission: 'compliance:read' },
    { name: 'Security Assurance', href: '/assurance', icon: Gauge, roles: ['all'], permission: 'assurance:read' },
    { name: 'Security Posture', href: '/posture', icon: TrendingUp, roles: ['super_admin', 'admin', 'security_manager'] },
    { name: 'Digital Twin', href: '/digital-twin', icon: GitBranch, roles: ['super_admin', 'admin', 'security_manager', 'security_analyst', 'developer'] },
    { name: 'Knowledge', href: '/knowledge', icon: BookOpen, roles: ['all'] },
  ] },
  { label: 'Manage', items: [
    { name: 'Users & RBAC', href: '/users', icon: Users, roles: ['super_admin', 'admin'] },
    { name: 'Audit Trail', href: '/audit', icon: ClipboardList, roles: ['super_admin', 'admin', 'auditor'], permission: 'audit:read' },
    { name: 'Notifications', href: '/notifications', icon: Bell, roles: ['all'] },
  ] },
  { label: 'System', items: [
    { name: 'Settings', href: '/settings', icon: Settings, roles: ['super_admin', 'admin', 'security_manager', 'developer'] },
    { name: 'System Monitor', href: '/system', icon: Monitor, roles: ['super_admin', 'admin'] },
  ] },
]

export const Layout = () => {
  const location = useLocation()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [commandOpen, setCommandOpen] = useState(false)
  const { user } = useAuthStore()

  const filteredGroups = useMemo(() => {
    if (!user) return []
    return NAV_GROUPS
      .map((group) => ({
        ...group,
        items: group.items.filter((item) =>
          (item.roles.includes('all') || item.roles.includes(user.role)) &&
          (!item.permission || hasPermission(user, item.permission)),
        ),
      }))
      .filter((group) => group.items.length > 0)
  }, [user])

  const flatForSidebar = useMemo(() => filteredGroups.flatMap((group) => group.items), [filteredGroups])

  return (
    <div className="aegis-page min-h-screen">
      <div className="pointer-events-none fixed inset-0 z-0 bg-[radial-gradient(circle_at_50%_-10%,color-mix(in_oklab,var(--primary)_5%,transparent),transparent_42%)]" />
      {mobileOpen && <button aria-label="Close navigation" className="fixed inset-0 z-40 bg-slate-950/60 backdrop-blur-md lg:hidden" onClick={() => setMobileOpen(false)} />}
      <Sidebar open={sidebarOpen} onOpenChange={setSidebarOpen} mobileOpen={mobileOpen} onMobileOpenChange={setMobileOpen} groups={filteredGroups} flatNavigation={flatForSidebar} currentPath={location.pathname} />
      <div className={`relative z-10 min-h-screen flex flex-col min-w-0 transition-[margin] duration-300 ${sidebarOpen ? 'lg:ml-64' : 'lg:ml-[72px]'}`}>
        <Header sidebarOpen={sidebarOpen} onSidebarToggle={() => setSidebarOpen((value) => !value)} onMobileToggle={() => setMobileOpen(true)} onCommandOpen={() => setCommandOpen(true)} />
        <main className="aegis-scrollbar flex-1 overflow-auto px-4 py-5 lg:px-8 lg:py-7">
          <div className="mx-auto w-full max-w-[1680px] animate-fade-in"><Outlet /></div>
        </main>
      </div>
      <CommandPalette open={commandOpen} onOpenChange={setCommandOpen} />
    </div>
  )
}
