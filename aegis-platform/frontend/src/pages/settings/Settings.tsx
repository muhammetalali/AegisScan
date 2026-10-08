import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Settings as SettingsIcon, Shield, Bell, Layers, FileText, Database, Key, Palette, Globe, Wrench } from 'lucide-react'
import { cn } from '@/utils/cn'
import { useThemeStore } from '@/stores/themeStore'
import { useLanguageStore } from '@/stores/languageStore'

const SECTIONS = [
  { id:'general', label:'General', icon: SettingsIcon, description:'Workspace navigation and account controls live in their own audited modules.', link:'/dashboard', linkLabel:'Open dashboard' },
  { id:'security', label:'Security', icon: Shield, description:'Security events, findings and governance are operated from the dedicated security workspaces.', link:'/security-events', linkLabel:'Security events' },
  { id:'auth', label:'Authentication', icon: Key, description:'Identity and access management are governed by existing Users & RBAC and API Key endpoints. Password reset and MFA enrollment are not available here.', link:'/users', linkLabel:'Users & RBAC' },
  { id:'notifications', label:'Notifications', icon: Bell, description:'View notifications in the live notifications workspace.', link:'/notifications', linkLabel:'Open notifications' },
  { id:'engines', label:'Engines', icon: Layers, description:'Scanner execution is governed per assessment and per supported capability. Global engine toggles are unavailable in this UI.', link:'/assess', linkLabel:'New assessment' },
  { id:'profiles', label:'Scanning Profiles', icon: FileText, description:'Assessment depth and capabilities are selected through the existing governed launcher; global profile editing is not available.', link:'/assess', linkLabel:'New assessment' },
  { id:'reports', label:'Reports', icon: FileText, description:'Review and export real reports from the report registry. A global report template editor is not available.', link:'/reports', linkLabel:'Open reports' },
  { id:'database', label:'Database', icon: Database, description:'Database administration is not exposed through the browser. Use the monitored service telemetry; no write controls are available here.', link:'/system', linkLabel:'System telemetry' },
  { id:'backup', label:'Backup', icon: Database, description:'Production backups are governed by the deployed recovery workflow. No browser backup or restore control is available.', link:'/system', linkLabel:'System telemetry' },
  { id:'api', label:'API', icon: Wrench, description:'Manage API access keys through the existing authenticated API Key lifecycle; project-scoped scanner credentials remain separate.', link:'/keys', linkLabel:'Manage API keys' },
  { id:'appearance', label:'Appearance', icon: Palette, description:'Choose a browser appearance. Changes take effect immediately and persist locally.' },
  { id:'language', label:'Language', icon: Globe, description:'Choose a language. Text direction updates immediately and persists locally.' },
  { id:'system', label:'System', icon: SettingsIcon, description:'Read actual health and service metrics from the platform. Arbitrary server settings are not writable from this page.', link:'/system', linkLabel:'System monitor' },
] as const

export const Settings = () => {
  const [active, setActive] = useState<(typeof SECTIONS)[number]['id']>('general')
  const { theme, setTheme } = useThemeStore()
  const { language, setLanguage } = useLanguageStore()
  const current = SECTIONS.find(section => section.id === active)!
  return (
    <div className="space-y-4">
      <div><h1 className="text-2xl font-bold flex items-center gap-2"><SettingsIcon className="h-6 w-6 text-primary" /> Settings</h1><p className="text-sm text-muted-foreground">Supported controls are live; unavailable platform settings are explicitly identified.</p></div>
      <div className="grid lg:grid-cols-4 gap-4">
        <nav className="rounded-xl border bg-card p-2 h-fit" aria-label="Settings sections">
          {SECTIONS.map(section=>(
            <button key={section.id} type="button" onClick={()=>setActive(section.id)} aria-pressed={active===section.id}
              className={cn('w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-start',active===section.id?'bg-primary text-primary-foreground':'hover:bg-accent')}>
              <section.icon className="h-4 w-4" />{section.label}
            </button>
          ))}
        </nav>
        <section className="lg:col-span-3 rounded-xl border bg-card p-6" aria-live="polite">
          <h2 className="font-semibold text-lg">{current.label}</h2>
          <p className="text-sm text-muted-foreground mt-2">{current.description}</p>
          {active==='appearance' && <fieldset className="mt-5 space-y-2"><legend className="font-medium text-sm">Theme</legend>
            <div className="flex flex-wrap gap-2">{(['light','dark','system'] as const).map(value=><button key={value} type="button" aria-pressed={theme===value}
              onClick={()=>setTheme(value)} className={cn('rounded-lg border px-4 py-2 text-sm capitalize',theme===value?'border-primary bg-primary/10':'hover:bg-accent')}>{value}</button>)}</div>
          </fieldset>}
          {active==='language' && <fieldset className="mt-5 space-y-2"><legend className="font-medium text-sm">Language</legend>
            <div className="flex flex-wrap gap-2">{(['ar','en'] as const).map(value=><button key={value} type="button" aria-pressed={language===value}
              onClick={()=>void setLanguage(value)} className={cn('rounded-lg border px-4 py-2 text-sm',language===value?'border-primary bg-primary/10':'hover:bg-accent')}>{value==='ar'?'العربية':'English'}</button>)}</div>
          </fieldset>}
          {'link' in current && <Link to={current.link} className="mt-5 inline-flex rounded-lg border px-4 py-2.5 text-sm hover:bg-accent">{current.linkLabel}</Link>}
        </section>
      </div>
    </div>
  )
}
