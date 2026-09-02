import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/authStore'
import { useThemeStore } from '@/stores/themeStore'
import { useLanguageStore } from '@/stores/languageStore'
import { Breadcrumbs } from './Breadcrumbs'
import { Menu, Sun, Moon, Globe, Bell, User, LogOut, Settings, ChevronDown, Search, Command, Shield } from 'lucide-react'
import { cn } from '@/utils/cn'
import { useQuery } from '@tanstack/react-query'
import { apiHelpers } from '@/services/api'

type NotificationPreview = { id: string; event_type: string; status: string; created_at: string }

export const Header = ({ sidebarOpen, onSidebarToggle, onMobileToggle, onCommandOpen }: {
  sidebarOpen: boolean
  onSidebarToggle: () => void
  onMobileToggle: () => void
  onCommandOpen: () => void
}) => {
  const { user, logout } = useAuthStore()
  const { resolvedTheme, toggleTheme } = useThemeStore()
  const { language, setLanguage, t } = useLanguageStore()
  const navigate = useNavigate()
  const [userOpen, setUserOpen] = useState(false)
  const userRef = useRef<HTMLDivElement>(null)
  const displayName = user ? `${user.first_name} ${user.last_name}`.trim() || user.email : ''
  const notificationQuery = useQuery<NotificationPreview[]>({
    queryKey: ['notifications-preview'],
    queryFn: () => apiHelpers.get<NotificationPreview[]>('/enterprise/notifications?limit=5'),
    staleTime: 30_000,
    retry: false,
  })

  useEffect(() => {
    const h = (event: MouseEvent) => {
      if (userRef.current && !userRef.current.contains(event.target as Node)) setUserOpen(false)
    }
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [])

  const switchLanguage = async () => { await setLanguage(language === 'ar' ? 'en' : 'ar') }

  return (
    <header className="sticky top-0 z-40 h-[72px] border-b border-border/70 bg-card/72 shadow-[0_12px_35px_rgba(0,0,0,.08)] backdrop-blur-2xl supports-[backdrop-filter]:bg-card/55">
      <div className="flex h-full items-center gap-3 px-4 lg:px-6">
        <button onClick={onMobileToggle} className="enterprise-icon-button rounded-xl border border-border/60 bg-background/30 p-2 lg:hidden" aria-label={t('Open navigation')}><Menu className="h-5 w-5" /></button>
        <button onClick={onSidebarToggle} className="enterprise-icon-button hidden rounded-xl border border-border/60 bg-background/30 p-2 lg:flex" aria-label={t('Toggle sidebar')}><Menu className="h-5 w-5" /></button>
        <div className="hidden min-w-0 flex-col justify-center md:flex"><Breadcrumbs /><div className="hidden text-[10px] font-medium tracking-wide text-muted-foreground lg:block">AegisScan / {t('Security Validation')}</div></div>
        <div className="flex flex-1 justify-center px-2"><button onClick={onCommandOpen} className="enterprise-control hidden w-full max-w-xl items-center gap-2 rounded-2xl border border-border/70 bg-background/35 px-4 py-2.5 text-sm text-muted-foreground shadow-inner transition-all hover:border-primary/35 hover:bg-background/55 sm:flex"><Search className="h-4 w-4" /><span className="flex-1 text-start">{t('Search validations, findings, assets...')}</span><span className="hidden items-center gap-1 rounded-md border border-border/70 bg-card/70 px-1.5 py-0.5 text-[10px] md:inline-flex"><Command className="h-3 w-3"/>K</span></button><button onClick={onCommandOpen} className="enterprise-icon-button rounded-xl border border-border/60 bg-background/30 p-2 sm:hidden" aria-label={t('Search')}><Search className="h-4 w-4"/></button></div>
        <div className="flex items-center gap-1.5">
          <Link to="/notifications" className="enterprise-icon-button relative rounded-xl border border-border/60 bg-background/30 p-2 transition-all" aria-label={t('Notifications')}><Bell className="h-4 w-4" />{notificationQuery.data?.length ? <span className="absolute -end-1 -top-1 min-w-4 rounded-full bg-primary px-1 text-center text-[9px] font-bold text-primary-foreground">{notificationQuery.data.length}</span> : null}</Link>
          <button onClick={toggleTheme} className="enterprise-icon-button rounded-xl border border-border/60 bg-background/30 p-2 transition-all" aria-label={t('Toggle theme')}>{resolvedTheme === 'dark' ? <Sun className="h-4 w-4"/> : <Moon className="h-4 w-4"/>}</button>
          <button onClick={switchLanguage} className="enterprise-control hidden items-center gap-1 rounded-xl border border-border/60 bg-background/30 px-2.5 py-2 text-xs font-semibold transition-all sm:flex" aria-label={t('Change language')}><Globe className="h-3.5 w-3.5"/>{language === 'ar' ? 'EN' : 'العربية'}</button>
          <div className="relative" ref={userRef}>
            <button onClick={() => setUserOpen(value => !value)} className={cn('enterprise-control flex items-center gap-2 rounded-xl border border-border/70 bg-background/35 py-1.5 pl-1.5 pr-2.5 shadow-sm transition-all', userOpen && 'bg-accent')}><div className="grid h-8 w-8 place-items-center rounded-lg bg-gradient-to-br from-primary to-violet-500 text-xs font-bold text-primary-foreground shadow-[0_6px_18px_color-mix(in_srgb,var(--primary)_24%,transparent)]">{user?.first_name?.[0] || 'A'}{user?.last_name?.[0] || ''}</div><span className="hidden max-w-[140px] truncate text-sm font-medium md:block">{displayName}</span><ChevronDown className="h-4 w-4 text-muted-foreground"/></button>
            {userOpen && <div className="absolute end-0 top-full z-50 mt-2 w-64 overflow-hidden rounded-2xl border border-border/70 bg-card/95 shadow-2xl backdrop-blur-2xl"><div className="border-b border-border/70 bg-background/35 px-4 py-4"><div className="flex items-center gap-2"><div className="grid h-9 w-9 place-items-center rounded-xl bg-primary text-primary-foreground"><User className="h-4 w-4"/></div><div className="min-w-0"><div className="truncate text-sm font-semibold">{displayName}</div><div className="flex items-center gap-1 text-xs capitalize text-muted-foreground"><Shield className="h-3 w-3"/>{user?.role}</div></div></div><div className="mt-2 truncate font-mono text-[10px] text-muted-foreground">{user?.email}</div></div><div className="p-1.5"><button onClick={()=>{setUserOpen(false);navigate('/settings')}} className="enterprise-menu-item w-full rounded-xl px-3 py-2.5 text-start text-sm"><Settings className="me-2 inline h-4 w-4"/>{t('Settings')}</button><button onClick={async()=>{await logout();setUserOpen(false)}} className="enterprise-menu-item w-full rounded-xl px-3 py-2.5 text-start text-sm text-destructive"><LogOut className="me-2 inline h-4 w-4"/>{t('Logout')}</button></div></div>}
          </div>
        </div>
      </div>
    </header>
  )
}
