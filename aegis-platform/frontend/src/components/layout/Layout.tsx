import { useState, useMemo } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { CommandPalette } from './CommandPalette'
import { useAuthStore } from '@/stores/authStore'
import {
  LayoutDashboard,
  FolderKanban,
  Server,
  Zap,
  Activity,
  Bug,
  FileText,
  ShieldCheck,
  BookOpen,
  GitBranch,
  TrendingUp,
  Users,
  Settings,
  Monitor,
  ClipboardList,
  Bell,
} from 'lucide-react'

// Enterprise IA — grouped, ordered by user journey
export const NAV_GROUPS = [
  {
    label: 'Overview',
    items: [
      { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard, roles: ['all'] },
    ],
  },
  {
    label: 'Workspace',
    items: [
      { name: 'Projects', href: '/projects', icon: FolderKanban, roles: ['all'] },
      { name: 'Assets', href: '/assets', icon: Server, roles: ['all'] },
    ],
  },
  {
    label: 'Validate',
    items: [
      { name: 'New Validation', href: '/validations/new', icon: Zap, roles: ['analyst','manager','admin'] },
      { name: 'Validations', href: '/scan', icon: Activity, roles: ['all'] },
      { name: 'Findings', href: '/vulnerabilities', icon: Bug, roles: ['all'] },
      { name: 'Evidence', href: '/reports', icon: FileText, roles: ['all'] },
    ],
  },
  {
    label: 'Analyze',
    items: [
      { name: 'Reports', href: '/reports', icon: FileText, roles: ['all'] },
      { name: 'Compliance', href: '/compliance', icon: ShieldCheck, roles: ['analyst','manager','admin','auditor'] },
      { name: 'Security Posture', href: '/posture', icon: TrendingUp, roles: ['manager','admin'] },
      { name: 'Digital Twin', href: '/digital-twin', icon: GitBranch, roles: ['analyst','manager','admin'] },
      { name: 'Knowledge', href: '/knowledge', icon: BookOpen, roles: ['all'] },
    ],
  },
  {
    label: 'Manage',
    items: [
      { name: 'Users & RBAC', href: '/users', icon: Users, roles: ['admin'] },
      { name: 'Audit Trail', href: '/audit', icon: ClipboardList, roles: ['admin','auditor'] },
      { name: 'Notifications', href: '/notifications', icon: Bell, roles: ['all'] },
    ],
  },
  {
    label: 'System',
    items: [
      { name: 'Settings', href: '/settings', icon: Settings, roles: ['admin'] },
      { name: 'System Monitor', href: '/system', icon: Monitor, roles: ['admin'] },
    ],
  },
]

export const Layout = () => {
  const location = useLocation()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [commandOpen, setCommandOpen] = useState(false)
  const { user } = useAuthStore()

  const filteredGroups = useMemo(() => {
    if (!user) return []
    return NAV_GROUPS.map(g => ({
      ...g,
      items: g.items.filter(it => it.roles.includes('all') || it.roles.includes(user.role)),
    })).filter(g => g.items.length > 0)
  }, [user])

  const flatForSidebar = useMemo(() => filteredGroups.flatMap(g => g.items), [filteredGroups])

  return (
    <div className="min-h-screen bg-background flex">
      {mobileOpen && <div className="fixed inset-0 z-40 bg-black/50 lg:hidden" onClick={()=>setMobileOpen(false)} />}

      <Sidebar
        open={sidebarOpen}
        onOpenChange={setSidebarOpen}
        mobileOpen={mobileOpen}
        onMobileOpenChange={setMobileOpen}
        groups={filteredGroups}
        flatNavigation={flatForSidebar}
        currentPath={location.pathname}
      />

      <div className={`flex-1 flex flex-col min-w-0 transition-all duration-300 ${sidebarOpen ? 'lg:pl-64' : 'lg:pl-20'}`}>
        <Header
          sidebarOpen={sidebarOpen}
          onSidebarToggle={()=>setSidebarOpen(!sidebarOpen)}
          onMobileToggle={()=>setMobileOpen(true)}
          onCommandOpen={()=>setCommandOpen(true)}
        />
        <main className="flex-1 p-4 lg:p-6 overflow-auto bg-muted/20">
          <Outlet />
        </main>
      </div>

      <CommandPalette open={commandOpen} onOpenChange={setCommandOpen} />
    </div>
  )
}
