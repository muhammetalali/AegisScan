import { NavLink, useLocation } from 'react-router-dom'
import { cn } from '@/utils/cn'
import { ChevronLeft, ChevronRight, CircleDot } from 'lucide-react'

interface NavItem { name: string; href: string; icon: any }
interface Group { label: string; items: NavItem[] }

export const Sidebar = ({ open, onOpenChange, mobileOpen, onMobileOpenChange, groups }: {
  open: boolean; onOpenChange: (v:boolean)=>void; mobileOpen: boolean; onMobileOpenChange:(v:boolean)=>void;
  groups: Group[]; flatNavigation: NavItem[]; currentPath: string
}) => {
  const location = useLocation()

  const renderGroups = (isMobile = false) => (
    <div className="flex-1 overflow-y-auto px-2 py-4 space-y-5">
      {groups.map(group => (
        <section key={group.label}>
          {(open || isMobile) && (
            <div className="px-2 mb-2 text-[10px] font-bold tracking-[0.16em] text-muted-foreground uppercase">
              {group.label}
            </div>
          )}
          {!open && !isMobile && <div className="h-px bg-border/70 mx-2 mb-2" />}
          <ul className="space-y-1">
            {group.items.map(item => {
              const Icon = item.icon
              const active = location.pathname === item.href || location.pathname.startsWith(item.href + '/')
              return (
                <li key={item.href}>
                  <NavLink
                    to={item.href}
                    onClick={() => isMobile && onMobileOpenChange(false)}
                    title={!open && !isMobile ? item.name : undefined}
                    className={cn(
                      'group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-[13px] font-medium transition-all duration-150',
                      active
                        ? 'bg-primary/10 text-primary shadow-[inset_0_0_0_1px_color-mix(in_srgb,var(--primary)_12%,transparent)]'
                        : 'text-muted-foreground hover:bg-accent/80 hover:text-accent-foreground',
                      !open && !isMobile && 'justify-center px-2'
                    )}
                  >
                    {active && <span className="absolute inset-y-1.5 start-0 w-0.5 rounded-full bg-primary" />}
                    <Icon className={cn('h-[17px] w-[17px] shrink-0', active && 'stroke-[2.4]')} />
                    {(open || isMobile) && <span className="truncate">{item.name}</span>}
                    {(open || isMobile) && active && <CircleDot className="ms-auto h-3 w-3 fill-current opacity-60" />}
                  </NavLink>
                </li>
              )
            })}
          </ul>
        </section>
      ))}
    </div>
  )

  const Brand = ({ mobile = false }) => (
    <div className={cn('flex h-16 items-center border-b px-3 shrink-0', mobile && 'px-4')}>
      <NavLink to="/dashboard" className="flex min-w-0 items-center gap-2.5 flex-1">
        <div className="relative grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-primary/20 bg-primary/10 p-1 shadow-[0_8px_24px_color-mix(in_srgb,var(--primary)_15%,transparent)]">
          <img src="/aegis-logo.svg" alt="AegisScan" className="h-7 w-7" />
          <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full bg-emerald-400 ring-2 ring-sidebar-background" />
        </div>
        {(open || mobile) && (
          <div className="min-w-0">
            <div className="truncate text-sm font-bold tracking-tight">AegisScan</div>
            <div className="truncate text-[9px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">Security Validation</div>
          </div>
        )}
      </NavLink>
      {!mobile && (
        <button onClick={() => onOpenChange(!open)} className="rounded-lg p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground" aria-label="Toggle sidebar">
          {open ? <ChevronLeft className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>
      )}
      {mobile && (
        <button onClick={() => onMobileOpenChange(false)} className="rounded-lg p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground" aria-label="Close navigation">
          <ChevronLeft className="h-5 w-5" />
        </button>
      )}
    </div>
  )

  return (
    <>
      <aside className={cn('fixed inset-y-0 start-0 z-50 hidden lg:flex flex-col bg-sidebar-background/95 text-sidebar-foreground border-e border-sidebar-border transition-[width] duration-200', open ? 'w-64' : 'w-[72px]')}>
        <Brand />
        {renderGroups()}
        <div className="border-t border-sidebar-border p-3 shrink-0">
          {open ? (
            <div className="rounded-xl border border-sidebar-border bg-sidebar-accent/40 p-3 shadow-[0_12px_35px_color-mix(in_srgb,black_12%,transparent)]">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,.65)]" />
                <span className="text-xs font-semibold">Platform operational</span>
              </div>
              <div className="mt-1 text-[10px] text-muted-foreground">15 engines · evidence-driven</div>
            </div>
          ) : <div className="text-center text-[9px] font-semibold text-muted-foreground">v1</div>}
        </div>
      </aside>

      {mobileOpen && (
        <aside className="fixed inset-y-0 start-0 z-50 flex w-72 flex-col bg-sidebar-background text-sidebar-foreground border-e border-sidebar-border shadow-2xl lg:hidden">
          <Brand mobile />
          {renderGroups(true)}
        </aside>
      )}
    </>
  )
}
