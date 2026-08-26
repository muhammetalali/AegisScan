import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { FolderKanban, Server, Activity, Bug, FileText, ShieldCheck, TrendingUp, Clock, Settings } from 'lucide-react'
import { cn } from '@/utils/cn'

const TABS = [
  { id:'overview', label:'Overview', icon: FolderKanban },
  { id:'assets', label:'Assets', icon: Server },
  { id:'validations', label:'Validations', icon: Activity },
  { id:'findings', label:'Findings', icon: Bug },
  { id:'evidence', label:'Evidence', icon: FileText },
  { id:'reports', label:'Reports', icon: FileText },
  { id:'compliance', label:'Compliance', icon: ShieldCheck },
  { id:'posture', label:'Posture', icon: TrendingUp },
  { id:'activity', label:'Activity', icon: Clock },
  { id:'settings', label:'Settings', icon: Settings },
]

export const ProjectDetail = () => {
  const { id } = useParams<{id:string}>()
  const [tab, setTab] = useState('overview')
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Link to="/projects" className="text-sm text-muted-foreground hover:text-foreground">Projects</Link>
        <span className="text-muted-foreground">/</span>
        <span className="font-mono text-sm font-medium">{id}</span>
      </div>
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2"><FolderKanban className="h-6 w-6 text-primary" /> E-Commerce Platform</h1>
        <p className="text-sm text-muted-foreground">Owner: Security Team • Assets 12 • Last Validation 2026-08-26 • Score 78</p>
      </div>
      <div className="flex gap-1 overflow-auto border-b">
        {TABS.map(t=>(
          <button key={t.id} onClick={()=>setTab(t.id)} className={cn('px-3 py-2 text-xs font-medium border-b-2 whitespace-nowrap inline-flex items-center gap-1', tab===t.id ? 'border-primary text-primary' : 'border-transparent text-muted-foreground')}>
            <t.icon className="h-3.5 w-3.5" />{t.label}
          </button>
        ))}
      </div>
      <div className="rounded-xl border bg-card p-6">
        {tab==='overview' && <div className="space-y-3"><div className="grid md:grid-cols-3 gap-3"><div className="rounded border p-3 text-center"><div className="text-xl font-bold">78/100</div><div className="text-xs text-muted-foreground">Security Score</div></div><div className="rounded border p-3 text-center"><div className="text-xl font-bold">12</div><div className="text-xs text-muted-foreground">Assets</div></div><div className="rounded border p-3 text-center"><div className="text-xl font-bold">3</div><div className="text-xs text-muted-foreground">Critical Findings</div></div></div><p className="text-sm text-muted-foreground">Project overview with validations, findings, evidence, reports, posture — linked to Workflow: Project → Asset → Validation → Finding → Evidence → Risk → Compliance → Remediation → Re-validation → Report</p></div>}
        {tab!=='overview' && <div className="text-sm text-muted-foreground">Section <span className="font-mono">{tab}</span> — data filtered by project {id}. Connects to `/api/validations?project_id={id}` and related resources.</div>}
      </div>
    </div>
  )
}
