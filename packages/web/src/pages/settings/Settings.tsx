import { useState } from 'react'
import { Settings as SettingsIcon, Shield, Bell, Layers, FileText, Database, Key, Palette, Globe, Wrench } from 'lucide-react'
import { cn } from '@/utils/cn'

const SECTIONS = [
  { id:'general', label:'General', icon: SettingsIcon },
  { id:'security', label:'Security', icon: Shield },
  { id:'auth', label:'Authentication', icon: Key },
  { id:'notifications', label:'Notifications', icon: Bell },
  { id:'engines', label:'Engines', icon: Layers },
  { id:'profiles', label:'Scanning Profiles', icon: FileText },
  { id:'reports', label:'Reports', icon: FileText },
  { id:'database', label:'Database', icon: Database },
  { id:'backup', label:'Backup', icon: Database },
  { id:'api', label:'API', icon: Wrench },
  { id:'appearance', label:'Appearance', icon: Palette },
  { id:'language', label:'Language', icon: Globe },
  { id:'system', label:'System', icon: SettingsIcon },
]

export const Settings = () => {
  const [active, setActive] = useState('general')
  return (
    <div className="space-y-4">
      <div><h1 className="text-2xl font-bold flex items-center gap-2"><SettingsIcon className="h-6 w-6 text-primary" /> Settings</h1><p className="text-sm text-muted-foreground">General • Security • Auth • Notifications • Engines • Profiles • Reports • DB • Backup • API • Appearance • Language • System</p></div>
      <div className="grid lg:grid-cols-4 gap-4">
        <div className="rounded-xl border bg-card p-2 h-fit">
          {SECTIONS.map(s=>(
            <button key={s.id} onClick={()=>setActive(s.id)} className={cn('w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm', active===s.id ? 'bg-primary text-primary-foreground' : 'hover:bg-accent')}>
              <s.icon className="h-4 w-4" />{s.label}
            </button>
          ))}
        </div>
        <div className="lg:col-span-3 rounded-xl border bg-card p-6">
          <h3 className="font-semibold capitalize">{active}</h3>
          <p className="text-sm text-muted-foreground mt-1">Section <span className="font-mono">{active}</span> — production hardening controls, feature flags, and system configuration. Connects to <span className="font-mono">/api/system/*</span> and Django settings.</p>
          <div className="mt-4 rounded border bg-muted/20 p-4 text-xs">
            <div>• Appearance: Dark/Light/System (already active)</div>
            <div>• Language: ar/en with RTL</div>
            <div>• Engines: 15 validation engines toggle</div>
            <div>• Backup: /system/backups • Feature Flags: /system/feature-flags</div>
          </div>
        </div>
      </div>
    </div>
  )
}
