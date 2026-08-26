import { useState, useRef, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/authStore'
import { useThemeStore } from '@/stores/themeStore'
import { useLanguageStore } from '@/stores/languageStore'
import { Breadcrumbs } from './Breadcrumbs'
import { Menu, Sun, Moon, Globe, Bell, User, LogOut, Settings, ChevronDown, Search, Command, Shield } from 'lucide-react'
import { cn } from '@/utils/cn'

export const Header = ({ sidebarOpen, onSidebarToggle, onMobileToggle, onCommandOpen }: {
  sidebarOpen: boolean
  onSidebarToggle: () => void
  onMobileToggle: () => void
  onCommandOpen: () => void
}) => {
  const { user, logout } = useAuthStore()
  const { resolvedTheme, toggleTheme } = useThemeStore()
  const { language, setLanguage } = useLanguageStore()
  const navigate = useNavigate()
  const [notifOpen, setNotifOpen] = useState(false)
  const [userOpen, setUserOpen] = useState(false)
  const notifRef = useRef<HTMLDivElement>(null)
  const userRef = useRef<HTMLDivElement>(null)
  const displayName = user ? `${user.first_name} ${user.last_name}`.trim() || user.email : ''

  useEffect(() => {
    const h = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) setNotifOpen(false)
      if (userRef.current && !userRef.current.contains(e.target as Node)) setUserOpen(false)
    }
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [])

  return (
    <header className="sticky top-0 z-40 h-[64px] bg-card/95 backdrop-blur supports-[backdrop-filter]:bg-card/80 border-b border-border">
      <div className="flex h-full items-center gap-3 px-4 lg:px-6">
        <button onClick={onMobileToggle} className="lg:hidden p-2 rounded-lg hover:bg-accent"><Menu className="h-5 w-5" /></button>
        <button onClick={onSidebarToggle} className="hidden lg:flex p-2 rounded-lg hover:bg-accent" aria-label="Toggle sidebar"><Menu className="h-5 w-5" /></button>

        <div className="hidden md:flex flex-col justify-center min-w-0">
          <Breadcrumbs />
          <div className="text-[11px] text-muted-foreground hidden lg:block">Enterprise Security Validation Platform • Real-time • Evidence-driven</div>
        </div>

        <div className="flex-1 flex justify-center px-2">
          <button onClick={onCommandOpen} className="hidden sm:flex items-center gap-2 w-full max-w-md px-3 py-2 rounded-lg border bg-muted/50 hover:bg-muted text-sm text-muted-foreground">
            <Search className="h-4 w-4" />
            <span className="flex-1 text-start">Search validations, findings, assets...</span>
            <span className="hidden md:inline-flex items-center gap-1 text-xs border rounded px-1.5 py-0.5 bg-card"><Command className="h-3 w-3" />K</span>
          </button>
          <button onClick={onCommandOpen} className="sm:hidden p-2 rounded-lg border bg-muted"><Search className="h-4 w-4" /></button>
        </div>

        <div className="flex items-center gap-1">
          <div className="relative" ref={notifRef}>
            <button onClick={()=>setNotifOpen(!notifOpen)} className={cn('relative p-2 rounded-lg hover:bg-accent', notifOpen && 'bg-accent')}>
              <Bell className="h-5 w-5" />
              <span className="absolute -top-0.5 -right-0.5 h-4 min-w-4 px-1 rounded-full bg-destructive text-destructive-foreground text-[10px] flex items-center justify-center">3</span>
            </button>
            {notifOpen && (
              <div className="absolute right-0 top-full mt-2 w-80 rounded-xl border bg-card shadow-xl overflow-hidden z-50">
                <div className="px-4 py-3 border-b flex justify-between items-center">
                  <span className="text-sm font-medium">Notifications</span>
                  <Link to="/notifications" onClick={()=>setNotifOpen(false)} className="text-xs text-primary hover:underline">View all</Link>
                </div>
                <div className="p-2 space-y-1">
                  {[
                    {title:'Validation completed', desc:'example.local — 9 findings', time:'2m ago'},
                    {title:'Critical finding', desc:'IDOR on /api/users', time:'18m ago'},
                    {title:'Report ready', desc:'Executive PDF generated', time:'1h ago'},
                  ].map((n,i)=>(
                    <div key={i} className="rounded-lg px-3 py-2 hover:bg-muted">
                      <div className="text-sm font-medium">{n.title}</div>
                      <div className="text-xs text-muted-foreground">{n.desc} • {n.time}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <button onClick={toggleTheme} className="p-2 rounded-lg hover:bg-accent" aria-label="Toggle theme">
            {resolvedTheme==='dark' ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
          </button>

          <button onClick={()=>setLanguage(language==='ar'?'en':'ar')} className="hidden sm:flex items-center gap-1 px-2.5 py-1.5 rounded-lg hover:bg-accent text-sm">
            <Globe className="h-4 w-4" />{language==='ar'?'العربية':'EN'}
          </button>

          <div className="relative" ref={userRef}>
            <button onClick={()=>setUserOpen(!userOpen)} className={cn('flex items-center gap-2 pl-1 pr-2 py-1 rounded-full hover:bg-accent border', userOpen && 'bg-accent')}>
              <div className="h-8 w-8 rounded-full bg-primary text-primary-foreground grid place-items-center text-sm font-medium">{user?.first_name?.[0]||'A'}{user?.last_name?.[0]||''}</div>
              <span className="hidden md:block text-sm max-w-[120px] truncate">{displayName}</span>
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            </button>
            {userOpen && (
              <div className="absolute right-0 top-full mt-2 w-64 rounded-xl border bg-card shadow-xl overflow-hidden z-50">
                <div className="px-4 py-3 border-b bg-muted/30">
                  <div className="flex items-center gap-2">
                    <div className="h-9 w-9 rounded-full bg-primary text-primary-foreground grid place-items-center"><User className="h-5 w-5" /></div>
                    <div>
                      <div className="text-sm font-medium">{displayName}</div>
                      <div className="text-xs text-muted-foreground capitalize flex items-center gap-1"><Shield className="h-3 w-3" />{user?.role}</div>
                    </div>
                  </div>
                  <div className="text-xs font-mono text-muted-foreground mt-1 truncate">{user?.email}</div>
                </div>
                <div className="p-1">
                  <button onClick={()=>{ setUserOpen(false); navigate('/settings')}} className="w-full flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-accent text-sm"><Settings className="h-4 w-4" />Settings</button>
                  <button onClick={async()=>{ await logout(); setUserOpen(false)}} className="w-full flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-accent text-sm text-destructive"><LogOut className="h-4 w-4" />Logout</button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  )
}
