import { useMemo, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { CommandPalette } from './CommandPalette'
import { useAuthStore } from '@/stores/authStore'
import { LayoutDashboard, FolderKanban, Server, Zap, Activity, Bug, FileText, ShieldCheck, BookOpen, GitBranch, TrendingUp, Users, Settings, Monitor, ClipboardList, Bell } from 'lucide-react'

export const NAV_GROUPS = [
  { label: 'Overview', items: [{ name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard, roles: ['all'] }] },
  { label: 'Workspace', items: [
    { name: 'Projects', href: '/projects', icon: FolderKanban, roles: ['all'] },
    { name: 'Assets', href: '/assets', icon: Server, roles: ['all'] },
  ]},
  { label: 'Validate', items: [
    { name: 'New Validation', href: '/validations/new', icon: Zap, roles: ['analyst','manager','admin'] },
    { name: 'Validations', href: '/scan', icon: Activity, roles: ['all'] },
    { name: 'Findings', href: '/vulnerabilities', icon: Bug, roles: ['all'] },
  ]},
  { label: 'Analyze', items: [
    { name: 'Reports', href: '/reports', icon: FileText, roles: ['all'] },
    { name: 'Compliance', href: '/compliance', icon: ShieldCheck, roles: ['analyst','manager','admin','auditor'] },
    { name: 'Security Posture', href: '/posture', icon: TrendingUp, roles: ['manager','admin'] },
    { name: 'Digital Twin', href: '/digital-twin', icon: GitBranch, roles: ['analyst','manager','admin'] },
    { name: 'Knowledge', href: '/knowledge', icon: BookOpen, roles: ['all'] },
  ]},
  { label: 'Manage', items: [
    { name: 'Users & RBAC', href: '/users', icon: Users, roles: ['admin'] },
    { name: 'Audit Trail', href: '/audit', icon: ClipboardList, roles: ['admin','auditor'] },
    { name: 'Notifications', href: '/notifications', icon: Bell, roles: ['all'] },
  ]},
  { label: 'System', items: [
    { name: 'Settings', href: '/settings', icon: Settings, roles: ['admin'] },
    { name: 'System Monitor', href: '/system', icon: Monitor, roles: ['admin'] },
  ]},
]

export const Layout = () => {
  const location = useLocation()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [commandOpen, setCommandOpen] = useState(false)
  const { user } = useAuthStore()

  const filteredGroups = useMemo(() => {
    if (!user) return []
    return NAV_GROUPS.map(group => ({
      ...group,
      items: group.items.filter(item => item.roles.includes('all') || item.roles.includes(user.role)),
    })).filter(group => group.items.length > 0)
  }, [user])

  const flatForSidebar = useMemo(() => filteredGroups.flatMap(group => group.items), [filteredGroups])

  return (
    <div className="min-h-screen bg-background">
      {mobileOpen && <button aria-label="Close navigation" className="fixed inset-0 z-40 bg-slate-950/50 backdrop-blur-sm lg:hidden" onClick={() => setMobileOpen(false)} />}
      <Sidebar open={sidebarOpen} onOpenChange={setSidebarOpen} mobileOpen={mobileOpen} onMobileOpenChange={setMobileOpen} groups={filteredGroups} flatNavigation={flatForSidebar} currentPath={location.pathname} />
      <div className={`min-h-screen flex flex-col min-w-0 transition-[margin] duration-200 ${sidebarOpen ? 'lg:ml-64' : 'lg:ml-[72px]'}`}>
        <Header sidebarOpen={sidebarOpen} onSidebarToggle={() => setSidebarOpen(value => !value)} onMobileToggle={() => setMobileOpen(true)} onCommandOpen={() => setCommandOpen(true)} />
        <main className="flex-1 overflow-auto px-4 py-5 lg:px-7 lg:py-6">
          <div className="mx-auto w-full max-w-[1600px] animate-fade-in"><Outlet /></div>
        </main>
      </div>
      <CommandPalette open={commandOpen} onOpenChange={setCommandOpen} />
    </div>
  )
}
