import { NavLink, useLocation } from 'react-router-dom'
import { cn } from '@/utils/cn'
import { ChevronLeft, ChevronRight, Shield } from 'lucide-react'

interface NavItem { name: string; href: string; icon: any }
interface Group { label: string; items: NavItem[] }

export const Sidebar = ({ open, onOpenChange, mobileOpen, onMobileOpenChange, groups, flatNavigation, currentPath }: {
  open: boolean; onOpenChange: (v:boolean)=>void; mobileOpen: boolean; onMobileOpenChange:(v:boolean)=>void;
  groups: Group[]; flatNavigation: NavItem[]; currentPath: string
}) => {
  const location = useLocation()
  const renderGroups = (isMobile=false) => (
    <div className="flex-1 overflow-y-auto py-3 px-2 space-y-4">
      {groups.map(g=>(
        <div key={g.label}>
          {open || isMobile ? <div className="px-2 mb-1 text-[11px] font-semibold tracking-widest text-muted-foreground uppercase">{g.label}</div> : <div className="h-px bg-border my-2 mx-2" />}
          <ul className="space-y-1">
            {g.items.map(item=>{
              const Icon = item.icon
              const active = location.pathname === item.href || location.pathname.startsWith(item.href + '/')
              return (
                <li key={item.href}>
                  <NavLink
                    to={item.href}
                    onClick={()=>isMobile&&onMobileOpenChange(false)}
                    className={cn(
                      'flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors',
                      active ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground',
                      !open && !isMobile ? 'justify-center' : ''
                    )}
                    title={!open && !isMobile ? item.name : undefined}
                  >
                    <Icon className="h-[18px] w-[18px] shrink-0" />
                    {(open || isMobile) && <span className="truncate">{item.name}</span>}
                  </NavLink>
                </li>
              )
            })}
          </ul>
        </div>
      ))}
    </div>
  )

  return (
    <>
      <aside className={cn(
        'fixed top-0 left-0 z-50 h-full bg-card border-r border-border flex flex-col transition-all duration-300',
        open ? 'w-64' : 'w-[72px]',
        'hidden lg:flex'
      )}>
        <div className="flex h-[64px] items-center justify-between px-3 border-b shrink-0">
          <NavLink to="/dashboard" className="flex items-center gap-2 min-w-0">
            <div className="h-8 w-8 rounded-lg bg-primary text-primary-foreground grid place-items-center shrink-0"><Shield className="h-5 w-5" /></div>
            {open && <span className="font-bold tracking-tight">AegisScan</span>}
          </NavLink>
          <button onClick={()=>onOpenChange(!open)} className="p-1.5 rounded-lg hover:bg-accent">
            {open ? <ChevronLeft className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </button>
        </div>
        {renderGroups(false)}
        <div className="p-3 border-t shrink-0">
          {open ? (
            <div className="rounded-lg bg-muted p-3">
              <div className="text-xs font-medium">Enterprise Platform</div>
              <div className="text-[11px] text-muted-foreground">15 engines • Real-time • Evidence-driven</div>
            </div>
          ) : <div className="text-[10px] text-center text-muted-foreground">v1.0</div>}
        </div>
      </aside>

      {mobileOpen && (
        <aside className="fixed inset-y-0 left-0 z-50 w-64 bg-card border-r flex flex-col lg:hidden">
          <div className="flex h-[64px] items-center justify-between px-4 border-b">
            <div className="flex items-center gap-2"><div className="h-8 w-8 rounded-lg bg-primary text-primary-foreground grid place-items-center"><Shield className="h-5 w-5" /></div><span className="font-bold">AegisScan</span></div>
            <button onClick={()=>onMobileOpenChange(false)} className="p-1.5 rounded-lg hover:bg-accent"><ChevronLeft className="h-5 w-5" /></button>
          </div>
          {renderGroups(true)}
        </aside>
      )}
    </>
  )
}
