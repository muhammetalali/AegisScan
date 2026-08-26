import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { FolderKanban, Plus, Search, MoreHorizontal, Play, Copy, Archive, Trash2, Download, Shield, Clock } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'
import { Skeleton } from '@/components/ui/skeleton'

type Project = { id: string; name: string; owner: string; assets: number; lastValidation: string; score: number; risk: string; status: string; updated: string }

const MOCK: Project[] = [
  { id: 'prj-001', name: 'E-Commerce Platform', owner: 'Security Team', assets: 12, lastValidation: '2026-08-26 14:20', score: 78, risk: 'high', status: 'active', updated: '2h ago' },
  { id: 'prj-002', name: 'API Gateway', owner: 'Platform Team', assets: 8, lastValidation: '2026-08-25 09:10', score: 92, risk: 'low', status: 'active', updated: '1d ago' },
  { id: 'prj-003', name: 'Mobile Banking', owner: 'FinTech Squad', assets: 21, lastValidation: '2026-08-24 18:40', score: 64, risk: 'critical', status: 'active', updated: '3d ago' },
]

export const Projects = () => {
  const [q, setQ] = useState('')
  const { data, isLoading } = useQuery({ queryKey: ['projects'], queryFn: async () => {
    try { return await apiHelpers.get<any>('/projects') } catch { return { items: MOCK } }
  }})
  const items: Project[] = (data?.items || MOCK).filter((p: Project) => !q || p.name.toLowerCase().includes(q.toLowerCase()))

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2"><FolderKanban className="h-6 w-6 text-primary" /> Projects</h1>
          <p className="text-sm text-muted-foreground">Enterprise project registry — owner, assets, last validation, score, risk, status</p>
        </div>
        <div className="flex gap-2">
          <Link to="/validations/new" className="px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm inline-flex items-center gap-1"><Plus className="h-4 w-4" /> New Validation</Link>
          <button className="px-3 py-2 rounded-lg border bg-card text-sm">New Project</button>
        </div>
      </div>

      <div className="rounded-xl border bg-card p-3 flex gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search projects, owner, tags..." className="w-full pl-8 pr-3 py-2 rounded-lg border bg-background text-sm" />
        </div>
        <span className="text-xs text-muted-foreground self-center">{items.length} projects</span>
      </div>

      {isLoading ? <Skeleton className="h-64 w-full" /> : (
        <div className="rounded-xl border bg-card overflow-hidden">
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b bg-muted/30 text-xs text-muted-foreground">
                <th className="text-start px-4 py-3 font-medium">Project</th>
                <th className="text-start px-4 py-3 font-medium">Owner</th>
                <th className="text-start px-4 py-3 font-medium">Assets</th>
                <th className="text-start px-4 py-3 font-medium">Last Validation</th>
                <th className="text-start px-4 py-3 font-medium">Security Score</th>
                <th className="text-start px-4 py-3 font-medium">Risk</th>
                <th className="text-start px-4 py-3 font-medium">Status</th>
                <th className="text-start px-4 py-3 font-medium">Updated</th>
                <th className="px-4 py-3"></th>
              </tr></thead>
              <tbody>
                {items.map(p=>(
                  <tr key={p.id} className="border-b hover:bg-muted/20">
                    <td className="px-4 py-3"><Link to={`/projects/${p.id}`} className="font-medium hover:underline flex items-center gap-2"><Shield className="h-4 w-4 text-primary" />{p.name}</Link></td>
                    <td className="px-4 py-3 text-muted-foreground">{p.owner}</td>
                    <td className="px-4 py-3">{p.assets}</td>
                    <td className="px-4 py-3 font-mono text-xs flex items-center gap-1"><Clock className="h-3 w-3" />{p.lastValidation}</td>
                    <td className="px-4 py-3"><span className={cn('px-2 py-0.5 rounded-full text-xs font-medium', p.score>=80 ? 'bg-emerald-500 text-white' : p.score>=60 ? 'bg-amber-500 text-white' : 'bg-destructive text-destructive-foreground')}>{p.score}</span></td>
                    <td className="px-4 py-3"><span className={cn('px-2 py-0.5 rounded-full text-xs capitalize', p.risk==='critical' ? 'bg-red-600 text-white' : p.risk==='high' ? 'bg-orange-500 text-white' : 'bg-emerald-500 text-white')}>{p.risk}</span></td>
                    <td className="px-4 py-3"><span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs">{p.status}</span></td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{p.updated}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        <Link to={`/projects/${p.id}`} className="p-1.5 rounded hover:bg-accent" title="Open"><FolderKanban className="h-4 w-4" /></Link>
                        <Link to="/validations/new" className="p-1.5 rounded hover:bg-accent" title="Run Validation"><Play className="h-4 w-4" /></Link>
                        <button className="p-1.5 rounded hover:bg-accent" title="More"><MoreHorizontal className="h-4 w-4" /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="px-4 py-3 border-t bg-muted/20 flex gap-2 text-xs">
            <span className="inline-flex items-center gap-1"><Copy className="h-3 w-3" />Duplicate</span>
            <span className="inline-flex items-center gap-1"><Archive className="h-3 w-3" />Archive</span>
            <span className="inline-flex items-center gap-1 text-destructive"><Trash2 className="h-3 w-3" />Delete</span>
            <span className="inline-flex items-center gap-1 ml-auto"><Download className="h-3 w-3" />Download Report</span>
          </div>
        </div>
      )}

      {items.length===0 && <div className="rounded-xl border border-dashed bg-card p-12 text-center"><FolderKanban className="h-8 w-8 mx-auto text-muted-foreground" /><p className="text-sm font-medium mt-2">No projects</p><p className="text-xs text-muted-foreground">Create your first project to group assets and validations</p></div>}
    </div>
  )
}
