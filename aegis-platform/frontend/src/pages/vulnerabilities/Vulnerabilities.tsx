import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Bug, Search, Filter, Tag, MoreHorizontal, Eye, Check, Clock, AlertTriangle, Shield } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'

const sevColor: any = { critical:'bg-red-600 text-white', high:'bg-orange-500 text-white', medium:'bg-amber-500 text-white', low:'bg-emerald-500 text-white', informational:'bg-slate-500 text-white' }
const statusOptions = ['open','confirmed','in_progress','resolved','accepted_risk','false_positive']

export const Vulnerabilities = () => {
  const [sev, setSev] = useState('')
  const [status, setStatus] = useState('')
  const [q, setQ] = useState('')
  const [sort, setSort] = useState<'severity'|'confidence'>('severity')

  const { data, isLoading } = useQuery({
    queryKey:['findings-center', sev, status, q],
    queryFn: async ()=>{
      const params = new URLSearchParams()
      if(sev) params.set('severity', sev)
      if(status) params.set('status', status)
      if(q) params.set('q', q)
      const qs = params.toString() ? `?${params}` : ''
      try { return await apiHelpers.get<any>(`/findings${qs}`) } catch { return {items:[], total:0} }
    }
  })

  const items = (data?.items || []).slice().sort((a:any,b:any)=>{
    if(sort==='confidence') return b.confidence - a.confidence
    const order:any = {critical:5, high:4, medium:3, low:2, informational:1}
    return (order[b.severity]||0)-(order[a.severity]||0)
  })

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2"><Bug className="h-6 w-6 text-primary" /> Findings Center</h1>
        <p className="text-sm text-muted-foreground">Critical • High • Medium • Low • Informational — with Search, Sort, Tags, Status, Project, Asset, Engine</p>
      </div>

      <div className="rounded-xl border bg-card p-3 space-y-3">
        <div className="flex flex-wrap gap-2 items-center">
          <div className="flex gap-1">
            {['','critical','high','medium','low','informational'].map(s=>(
              <button key={s} onClick={()=>setSev(s)} className={cn('px-2.5 py-1 rounded-full text-xs capitalize border', sev===s ? 'bg-primary text-primary-foreground border-primary' : 'bg-card hover:bg-accent')}>{s||'All'}</button>
            ))}
          </div>
          <div className="h-6 w-px bg-border mx-1" />
          <div className="flex gap-1">
            {['','open','reviewed'].map(s=>(
              <button key={s} onClick={()=>setStatus(s)} className={cn('px-2 py-1 rounded-full text-xs capitalize border', status===s ? 'bg-primary text-primary-foreground' : 'bg-card')}>{s||'Any status'}</button>
            ))}
          </div>
          <select value={sort} onChange={e=>setSort(e.target.value as any)} className="ml-auto px-2 py-1.5 rounded-lg border bg-background text-xs">
            <option value="severity">Sort: Severity</option><option value="confidence">Sort: Confidence</option>
          </select>
        </div>

        <div className="flex gap-2">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search title, asset, category, tags, engine..." className="w-full pl-8 pr-3 py-2 rounded-lg border bg-background text-sm" />
          </div>
          <span className="text-xs text-muted-foreground self-center">{data?.total ?? 0} findings {data?.simulation && <span className="ml-2 inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-amber-100 text-amber-700 text-[11px]"><AlertTriangle className="h-3 w-3" />Demo</span>}</span>
        </div>
      </div>

      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="overflow-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b bg-muted/30 text-xs text-muted-foreground">
              <th className="text-start px-3 py-2">Severity</th>
              <th className="text-start px-3 py-2">Finding</th>
              <th className="text-start px-3 py-2">Asset</th>
              <th className="text-start px-3 py-2">Validation</th>
              <th className="text-start px-3 py-2">Confidence</th>
              <th className="text-start px-3 py-2">Status</th>
              <th className="text-start px-3 py-2">Actions</th>
            </tr></thead>
            <tbody>
              {isLoading ? <tr><td colSpan={7} className="px-4 py-8 text-center text-sm text-muted-foreground">Loading...</td></tr> :
                items.length===0 ? <tr><td colSpan={7} className="px-4 py-12 text-center"><Bug className="h-6 w-6 mx-auto text-muted-foreground" /><div className="text-sm font-medium mt-2">No findings</div><div className="text-xs text-muted-foreground">Run a validation to generate findings</div></td></tr> :
                items.map((f:any)=>(
                  <tr key={f.id} className="border-b hover:bg-muted/30">
                    <td className="px-3 py-2"><span className={cn('px-2 py-0.5 rounded text-[11px] font-medium capitalize', sevColor[f.severity])}>{f.severity}</span></td>
                    <td className="px-3 py-2">
                      <Link to={`/vulnerabilities/${f.id}`} className="font-medium hover:underline">{f.title}</Link>
                      <div className="text-[11px] text-muted-foreground flex gap-1 items-center"><Tag className="h-3 w-3" />{f.category} • {f.cwe} • CVSS {f.cvss}</div>
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">{f.asset}</td>
                    <td className="px-3 py-2 font-mono text-xs"><Link to={`/validations/${f.validation_id}/results`} className="hover:underline">{f.validation_id}</Link></td>
                    <td className="px-3 py-2"><span className={cn('px-1.5 py-0.5 rounded text-xs', f.confidence>=90 ? 'bg-emerald-500 text-white' : f.confidence>=80 ? 'bg-primary text-primary-foreground' : 'bg-muted')}>{f.confidence}%</span></td>
                    <td className="px-3 py-2"><span className={cn('px-1.5 py-0.5 rounded text-[11px] border capitalize', f.status==='reviewed' ? 'bg-emerald-50 border-emerald-200 text-emerald-700' : 'bg-amber-50 border-amber-200 text-amber-700')}>{f.status}</span></td>
                    <td className="px-3 py-2">
                      <div className="flex gap-1">
                        <Link to={`/vulnerabilities/${f.id}`} className="p-1.5 rounded hover:bg-accent" title="View Evidence"><Eye className="h-4 w-4" /></Link>
                        <button className="p-1.5 rounded hover:bg-accent" title="Assign"><Shield className="h-4 w-4" /></button>
                        <button className="p-1.5 rounded hover:bg-accent" title="Validate"><Check className="h-4 w-4" /></button>
                        <button className="p-1.5 rounded hover:bg-accent"><MoreHorizontal className="h-4 w-4" /></button>
                      </div>
                    </td>
                  </tr>
                ))
              }
            </tbody>
          </table>
        </div>
        <div className="px-3 py-2 border-t bg-muted/20 flex gap-2 text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1"><Clock className="h-3 w-3" />Status: Open → Confirmed → In Progress → Resolved → Accepted Risk → False Positive</span>
          <span className="ml-auto">Actions: Assign • Add Note • Change Status • Validate • Create Ticket • View Evidence</span>
        </div>
      </div>
    </div>
  )
}
