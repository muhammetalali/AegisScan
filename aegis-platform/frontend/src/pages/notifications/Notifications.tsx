import { Bell, Check, AlertTriangle, FileText, Activity } from 'lucide-react'
import { cn } from '@/utils/cn'
const NOTIFS = [
  { id:1, type:'validation.completed', title:'Validation completed', desc:'example.local — 9 findings', time:'2m ago', icon: Activity, color:'text-emerald-500' },
  { id:2, type:'critical.finding', title:'Critical finding', desc:'IDOR on /api/users', time:'18m ago', icon: AlertTriangle, color:'text-red-500' },
  { id:3, type:'report.ready', title:'Report ready', desc:'Executive PDF generated', time:'1h ago', icon: FileText, color:'text-primary' },
  { id:4, type:'validation.failed', title:'Validation failed', desc:'Target unreachable', time:'3h ago', icon: AlertTriangle, color:'text-amber-500' },
]
export const Notifications = () => {
  return (
    <div className="space-y-4 max-w-3xl mx-auto">
      <div><h1 className="text-2xl font-bold flex items-center gap-2"><Bell className="h-6 w-6 text-primary" /> Notifications</h1><p className="text-sm text-muted-foreground">Toast • Notification Center • Real-time WebSocket Events</p></div>
      <div className="rounded-xl border bg-card overflow-hidden">
        {NOTIFS.map(n=>(
          <div key={n.id} className="flex gap-3 px-4 py-3 border-b last:border-0 hover:bg-muted/20">
            <n.icon className={cn('h-5 w-5 mt-0.5', n.color)} />
            <div className="flex-1">
              <div className="text-sm font-medium">{n.title}</div>
              <div className="text-xs text-muted-foreground">{n.desc} • {n.time} • {n.type}</div>
            </div>
            <span className="text-xs px-2 py-0.5 rounded bg-muted self-center">New</span>
          </div>
        ))}
      </div>
      <div className="rounded-xl border bg-card p-4">
        <h3 className="text-sm font-semibold">WebSocket Events</h3>
        <div className="mt-2 font-mono text-xs bg-black text-green-400 p-3 rounded h-24 overflow-auto">
          <div>23:41:08 validation.completed — example.local</div>
          <div>23:41:12 finding.created — IDOR</div>
          <div>23:41:17 report.ready — Executive PDF</div>
        </div>
      </div>
    </div>
  )
}
