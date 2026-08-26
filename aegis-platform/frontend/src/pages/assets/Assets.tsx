import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Server, Plus, Search, Globe, Code2, Network, File, Container, Tag, MoreHorizontal, Play, Eye } from 'lucide-react'
import { cn } from '@/utils/cn'

const TYPES = [
  { id: 'code', label: 'Source Code', icon: Code2 },
  { id: 'url', label: 'Website URL', icon: Globe },
  { id: 'ip', label: 'IP Address', icon: Network },
  { id: 'domain', label: 'Domain', icon: Globe },
  { id: 'api', label: 'API Endpoint', icon: Server },
  { id: 'file', label: 'Uploaded File', icon: File },
  { id: 'docker', label: 'Docker Image', icon: Container },
  { id: 'range', label: 'Network Range', icon: Network },
]

const ASSETS = [
  { id:'ast-001', name:'api.example.local', type:'api', env:'production', project:'E-Commerce', tech:'Node.js', tags:['critical','external'], status:'active', owner:'Platform Team' },
  { id:'ast-002', name:'192.168.1.10', type:'ip', env:'staging', project:'API Gateway', tech:'—', tags:['internal'], status:'active', owner:'Security Team' },
  { id:'ast-003', name:'C:\\Projects\\MyApp', type:'code', env:'development', project:'Mobile Banking', tech:'React', tags:['code','review'], status:'active', owner:'FinTech Squad' },
  { id:'ast-004', name:'https://example.local', type:'url', env:'production', project:'E-Commerce', tech:'Next.js', tags:['web'], status:'active', owner:'Security Team' },
]

export const Assets = () => {
  const [q,setQ]=useState('')
  const [type,setType]=useState('')
  const [env,setEnv]=useState('')
  const filtered = ASSETS.filter(a=> (!q || a.name.toLowerCase().includes(q.toLowerCase())) && (!type || a.type===type) && (!env || a.env===env))

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2"><Server className="h-6 w-6 text-primary" /> Assets</h1>
          <p className="text-sm text-muted-foreground">Source Code • Website URL • IP • Domain • API • File • Docker • Network Range — with Environment & Tags</p>
        </div>
        <button className="px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm inline-flex items-center gap-1"><Plus className="h-4 w-4" /> Add Asset</button>
      </div>

      <div className="flex flex-wrap gap-2">
        {TYPES.map(t=>(
          <button key={t.id} onClick={()=>setType(type===t.id?'':t.id)} className={cn('px-3 py-1.5 rounded-full border text-xs inline-flex items-center gap-1', type===t.id ? 'bg-primary text-primary-foreground border-primary' : 'bg-card hover:bg-accent')}>
            <t.icon className="h-3.5 w-3.5" />{t.label}
          </button>
        ))}
      </div>

      <div className="rounded-xl border bg-card p-3 flex flex-wrap gap-2">
        <div className="relative flex-1 max-w-sm"><Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" /><input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search name, tags, tech..." className="w-full pl-8 pr-3 py-2 rounded-lg border bg-background text-sm" /></div>
        <select value={env} onChange={e=>setEnv(e.target.value)} className="px-3 py-2 rounded-lg border bg-background text-sm">
          <option value="">All Environments</option><option value="development">Development</option><option value="staging">Staging</option><option value="production">Production</option>
        </select>
        <span className="text-xs text-muted-foreground self-center">{filtered.length} assets</span>
      </div>

      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="overflow-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b bg-muted/30 text-xs text-muted-foreground">
              <th className="text-start px-4 py-3">Name</th><th className="text-start px-4 py-3">Type</th><th className="text-start px-4 py-3">Environment</th><th className="text-start px-4 py-3">Project</th><th className="text-start px-4 py-3">Technology</th><th className="text-start px-4 py-3">Tags</th><th className="text-start px-4 py-3">Status</th><th className="text-start px-4 py-3">Owner</th><th className="px-4 py-3"></th>
            </tr></thead>
            <tbody>
              {filtered.map(a=>(
                <tr key={a.id} className="border-b hover:bg-muted/20">
                  <td className="px-4 py-3 font-mono text-xs font-medium">{a.name}</td>
                  <td className="px-4 py-3"><span className="px-2 py-0.5 rounded-full bg-muted text-xs capitalize">{a.type}</span></td>
                  <td className="px-4 py-3"><span className={cn('px-2 py-0.5 rounded-full text-xs', a.env==='production' ? 'bg-red-500 text-white' : a.env==='staging' ? 'bg-amber-500 text-white' : 'bg-emerald-500 text-white')}>{a.env}</span></td>
                  <td className="px-4 py-3">{a.project}</td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{a.tech}</td>
                  <td className="px-4 py-3"><span className="inline-flex gap-1">{a.tags.map(t=><span key={t} className="px-1.5 py-0.5 rounded bg-muted text-[11px] inline-flex items-center gap-1"><Tag className="h-3 w-3" />{t}</span>)}</span></td>
                  <td className="px-4 py-3"><span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs">{a.status}</span></td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{a.owner}</td>
                  <td className="px-4 py-3"><div className="flex gap-1"><Link to="/validations/new" className="p-1.5 rounded hover:bg-accent" title="Validate"><Play className="h-4 w-4" /></Link><button className="p-1.5 rounded hover:bg-accent" title="View"><Eye className="h-4 w-4" /></button><button className="p-1.5 rounded hover:bg-accent"><MoreHorizontal className="h-4 w-4" /></button></div></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
