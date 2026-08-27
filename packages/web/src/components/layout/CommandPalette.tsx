import { useEffect, useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, LayoutDashboard, FolderKanban, Server, Play, Bug, FileText, ShieldCheck, TrendingUp, GitBranch, BookOpen, Users, ClipboardList, Bell, Settings, Monitor, Zap } from 'lucide-react'

const ITEMS = [
  { label: 'Dashboard', href: '/dashboard', icon: LayoutDashboard, kws: 'home overview' },
  { label: 'New Validation', href: '/validations/new', icon: Zap, kws: 'scan validation url ip code api' },
  { label: 'Projects', href: '/projects', icon: FolderKanban, kws: 'project' },
  { label: 'Assets', href: '/assets', icon: Server, kws: 'asset host domain' },
  { label: 'Findings', href: '/reports', icon: Bug, kws: 'vulnerability finding' },
  { label: 'Evidence', href: '/reports', icon: FileText, kws: 'evidence' },
  { label: 'Reports', href: '/reports', icon: FileText, kws: 'report pdf' },
  { label: 'Compliance', href: '/compliance', icon: ShieldCheck, kws: 'nist iso pci' },
  { label: 'Security Posture', href: '/posture', icon: TrendingUp, kws: 'posture risk trend' },
  { label: 'Digital Twin', href: '/digital-twin', icon: GitBranch, kws: 'twin simulation' },
  { label: 'Knowledge', href: '/knowledge', icon: BookOpen, kws: 'knowledge' },
  { label: 'Users & RBAC', href: '/users', icon: Users, kws: 'user role' },
  { label: 'Audit Trail', href: '/audit', icon: ClipboardList, kws: 'audit log' },
  { label: 'Notifications', href: '/notifications', icon: Bell, kws: 'notification' },
  { label: 'Settings', href: '/settings', icon: Settings, kws: 'setting' },
  { label: 'System Monitoring', href: '/system', icon: Monitor, kws: 'system health' },
]

export const CommandPalette = ({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) => {
  const [q, setQ] = useState('')
  const navigate = useNavigate()
  const filtered = useMemo(() => {
    if (!q) return ITEMS
    const l = q.toLowerCase()
    return ITEMS.filter(i => i.label.toLowerCase().includes(l) || i.kws.includes(l) || i.href.includes(l))
  }, [q])

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); onOpenChange(!open) }
      if (e.key === 'Escape') onOpenChange(false)
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [open, onOpenChange])

  useEffect(() => { if (!open) setQ('') }, [open])

  if (!open) return null
  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center pt-[20vh]" aria-modal="true">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => onOpenChange(false)} />
      <div className="relative w-full max-w-xl bg-card border rounded-xl shadow-2xl overflow-hidden animate-slide-in-from-top">
        <div className="flex items-center gap-2 px-4 py-3 border-b">
          <Search className="h-4 w-4 text-muted-foreground" />
          <input autoFocus value={q} onChange={e=>setQ(e.target.value)} placeholder="Search pages, validations, findings... (Ctrl+K)" className="flex-1 bg-transparent outline-none text-sm placeholder:text-muted-foreground" />
          <span className="text-xs px-1.5 py-0.5 rounded border bg-muted">ESC</span>
        </div>
        <div className="max-h-80 overflow-auto p-2">
          {filtered.length===0 ? <div className="py-8 text-center text-sm text-muted-foreground">No results</div> :
            <ul className="space-y-1">
              {filtered.map(item => (
                <li key={item.href}>
                  <button onClick={()=>{ onOpenChange(false); navigate(item.href)}} className="w-full flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-accent text-start">
                    <item.icon className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm">{item.label}</span>
                    <span className="ml-auto text-xs text-muted-foreground">{item.href}</span>
                  </button>
                </li>
              ))}
            </ul>
          }
        </div>
        <div className="px-3 py-2 border-t bg-muted/20 text-xs text-muted-foreground flex justify-between">
          <span>↑↓ Navigate • Enter Select</span>
          <span>AegisScan Command</span>
        </div>
      </div>
    </div>
  )
}
