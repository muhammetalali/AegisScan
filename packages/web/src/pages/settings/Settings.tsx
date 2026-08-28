import { useEffect, useMemo, useState } from 'react'
import { AlertCircle, CheckCircle2, Key, Loader2, Palette, Save, Settings as SettingsIcon, Shield, SlidersHorizontal, UserRound } from 'lucide-react'
import { cn } from '@/utils/cn'
import { useAuthStore } from '@/stores/authStore'

const SECTIONS = [
  { id: 'general', label: 'General', icon: SettingsIcon },
  { id: 'security', label: 'Security', icon: Shield },
  { id: 'authentication', label: 'Authentication', icon: Key },
  { id: 'appearance', label: 'Appearance', icon: Palette },
  { id: 'system', label: 'System', icon: SlidersHorizontal },
]

export const Settings = () => {
  const { user, updateProfile, loading, error, setError } = useAuthStore()
  const [active, setActive] = useState('general')
  const [name, setName] = useState('')
  const [saved, setSaved] = useState(false)
  const [theme, setTheme] = useState<'system' | 'light' | 'dark'>(() => (document.documentElement.classList.contains('dark') ? 'dark' : 'light'))

  useEffect(() => {
    setName([user?.first_name, user?.last_name].filter(Boolean).join(' '))
  }, [user])

  const role = useMemo(() => user?.role ? String(user.role) : 'Authenticated user', [user])
  const saveProfile = async () => {
    setSaved(false); setError(null)
    const parts = name.trim().split(/\s+/).filter(Boolean)
    try {
      await updateProfile({ first_name: parts[0] || '', last_name: parts.slice(1).join(' ') })
      setSaved(true)
    } catch { /* store exposes the actionable API error */ }
  }

  const applyTheme = (value: 'system' | 'light' | 'dark') => {
    setTheme(value)
    const root = document.documentElement
    root.classList.toggle('dark', value === 'dark' || (value === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches))
    localStorage.setItem('aegis-theme', value)
  }

  return <div className="space-y-6">
    <header><h1 className="flex items-center gap-2 text-2xl font-bold"><SettingsIcon className="h-6 w-6 text-primary" /> Settings</h1><p className="mt-1 text-sm text-muted-foreground">Operational account and platform preferences. Changes are persisted only through real application controls.</p></header>
    <div className="grid gap-4 lg:grid-cols-[220px_1fr]">
      <nav className="h-fit rounded-xl border bg-card p-2" aria-label="Settings sections">
        {SECTIONS.map((section) => { const Icon = section.icon; return <button key={section.id} type="button" onClick={() => setActive(section.id)} className={cn('flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm', active === section.id ? 'bg-primary text-primary-foreground' : 'hover:bg-accent')}><Icon className="h-4 w-4" />{section.label}</button> })}
      </nav>
      <main className="rounded-xl border bg-card p-6">
        {active === 'general' && <section className="space-y-5"><div><h2 className="font-semibold">Profile</h2><p className="text-sm text-muted-foreground">Identity information for the authenticated account.</p></div><div className="grid gap-4 sm:grid-cols-2"><label className="space-y-1 sm:col-span-2"><span className="text-sm font-medium">Name</span><div className="relative"><UserRound className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><input value={name} onChange={(event) => setName(event.target.value)} className="h-10 w-full rounded-lg border bg-background pl-9 pr-3 text-sm outline-none focus:ring-2 focus:ring-primary/30" /></div></label><div><span className="text-xs text-muted-foreground">Email</span><p className="mt-1 font-medium">{user?.email || '—'}</p></div><div><span className="text-xs text-muted-foreground">Role</span><p className="mt-1 font-medium capitalize">{role.replace('_', ' ')}</p></div></div><button type="button" disabled={loading || !user} onClick={() => void saveProfile()} className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50">{loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Save profile</button>{saved && <span className="ml-3 inline-flex items-center gap-1 text-sm text-emerald-600"><CheckCircle2 className="h-4 w-4" /> Saved</span>}{error && <div className="mt-4 flex items-start gap-2 rounded-lg border border-destructive/20 bg-destructive/10 p-3 text-sm text-destructive"><AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />{error}</div>}</section>}
        {active === 'security' && <section className="space-y-4"><div><h2 className="font-semibold">Security posture</h2><p className="text-sm text-muted-foreground">Session state is based on the authenticated account and server responses.</p></div><div className="rounded-lg border p-4"><div className="font-medium">Account</div><div className="mt-1 text-sm text-muted-foreground">{user?.is_active === false ? 'Inactive account' : 'Active account'} · {user?.is_verified ? 'Verified' : 'Verification status unavailable'}</div></div><div className="rounded-lg border p-4"><div className="font-medium">Two-factor authentication</div><div className="mt-1 text-sm text-muted-foreground">Use the Authentication section to manage server-backed 2FA where enabled for this account.</div></div></section>}
        {active === 'authentication' && <section className="space-y-4"><div><h2 className="font-semibold">Authentication</h2><p className="text-sm text-muted-foreground">JWT access/refresh sessions and account verification are controlled by the authentication service.</p></div><div className="rounded-lg border p-4"><div className="text-sm font-medium">Current session</div><div className="mt-1 text-sm text-muted-foreground">{user ? `Signed in as ${user.email}` : 'No authenticated user'}</div></div><div className="rounded-lg border p-4"><div className="text-sm font-medium">Token persistence</div><div className="mt-1 text-sm text-muted-foreground">The selected remember-me mode controls whether the client persists the authenticated session in local or session storage.</div></div></section>}
        {active === 'appearance' && <section className="space-y-4"><div><h2 className="font-semibold">Appearance</h2><p className="text-sm text-muted-foreground">This preference is applied locally and persisted in the browser.</p></div><div className="grid gap-2 sm:grid-cols-3">{(['system','light','dark'] as const).map((value) => <button key={value} type="button" onClick={() => applyTheme(value)} className={cn('rounded-lg border p-4 text-left text-sm capitalize', theme === value ? 'border-primary bg-primary/5 ring-2 ring-primary/20' : 'hover:bg-accent')}>{value}</button>)}</div></section>}
        {active === 'system' && <section className="space-y-4"><div><h2 className="font-semibold">System</h2><p className="text-sm text-muted-foreground">Runtime health belongs to the live service health endpoints; this page does not fabricate infrastructure state.</p></div><div className="rounded-lg border p-4"><div className="text-sm font-medium">Frontend</div><div className="mt-1 text-sm text-muted-foreground">Build-time configuration and API routing are supplied by the deployed environment.</div></div></section>}
      </main>
    </div>
  </div>
}
