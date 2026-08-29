import { useMemo, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { CommandPalette } from './CommandPalette'
import { NAV_GROUPS, type NavItem } from './navConfig'
import { useAuthStore } from '@/stores/authStore'
import { hasPermission } from '@/auth/rbac'

export { NAV_GROUPS }

type NavGroup = { label: string; items: NavItem[] }

export const Layout = () => {
  const location = useLocation()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [commandOpen, setCommandOpen] = useState(false)
  const { user } = useAuthStore()

  const filteredGroups = useMemo<NavGroup[]>(() => {
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
