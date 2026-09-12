import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import { ShieldCheck, Layers, Bug, FileText, Network, Route, Shield, ClipboardCheck, Download, Search, Eye, ChevronRight, Braces } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'
import Editor from '@monaco-editor/react'

type Tab = 'overview'|'findings'|'evidence'|'graph'|'paths'|'controls'|'compliance'

const TABS: {id: Tab; label: string; icon: any}[] = [
  {id:'overview', label:'Overview', icon: Layers},
  {id:'findings', label:'Findings', icon: Bug},
  {id:'evidence', label:'Evidence', icon: FileText},
  {id:'graph', label:'Evidence Graph', icon: Network},
  {id:'paths', label:'Attack Paths', icon: Route},
  {id:'controls', label:'Controls', icon: Shield},
  {id:'compliance', label:'Compliance', icon: ClipboardCheck},
]

const sevColor: Record<string,string> = {
  critical:'bg-red-600 text-white',
  high:'bg-orange-500 text-white',
  medium:'bg-amber-500 text-white',
  low:'bg-emerald-500 text-white',
  informational:'bg-slate-500 text-white',
}

export const ValidationResults = () => {
  const { id } = useParams<{id:string}>()
  const [tab, setTab] = useState<Tab>('overview')
  const [sevFilter, setSevFilter] = useState<string>('')
  const [q, setQ] = useState('')
  const [selectedFinding, setSelectedFinding] = useState<any>(null)
  const [evidenceFinding, setEvidenceFinding] = useState<string>('')

  const { data: results, isLoading } = useQuery({
    queryKey: ['val-results', id],
    queryFn: async () => apiHelpers.get<any>(`/validations/${id}/results`),
    enabled: !!id,
  })

  const { data: findingsData } = useQuery({
    queryKey: ['val-findings', id, sevFilter, q],
    queryFn: async () => apiHelpers.get<any>(`/validations/${id}/findings${sevFilter?`?severity=${sevFilter}`:''}${q?`${sevFilter?'&':'?'}q=${encodeURIComponent(q)}`:''}`),
    enabled: !!id && tab==='findings',
  })

  const { data: evidenceData } = useQuery({
    queryKey: ['val-evidence', id, evidenceFinding],
    queryFn: async () => apiHelpers.get<any>(`/validations/${id}/evidence${evidenceFinding?`?finding_id=${evidenceFinding}`:''}`),
    enabled: !!id && (tab==='evidence' || !!selectedFinding),
  })

  const { data: graphData } = useQuery({
    queryKey: ['val-graph', id],
    queryFn: async () => apiHelpers.get<any>(`/validations/${id}/graph`),
    enabled: !!id && tab==='graph',
  })

  const { data: pathsData } = useQuery({
    queryKey: ['val-paths', id],
    queryFn: async () => apiHelpers.get<any>(`/validations/${id}/attack-paths`),
    enabled: !!id && tab==='paths',
  })

  const { data: controlsData } = useQuery({
    queryKey: ['val-controls', id],
    queryFn: async () => apiHelpers.get<any>(`/validations/${id}/controls`),
    enabled: !!id && tab==='controls',
  })

  const { data: complianceData } = useQuery({
    queryKey: ['val-compliance', id],
    queryFn: async () => apiHelpers.get<any>(`/validations/${id}/compliance`),
    enabled: !!id && tab==='compliance',
  })

  const { data: validationMeta } = useQuery({
    queryKey: ['val-meta', id],
    queryFn: async () => apiHelpers.get<any>(`/validations/${id}`),
    enabled: !!id,
  })

  const overview = results?.overview
  const findings = findingsData?.items || []
  const evidences = evidenceData?.items || []

  const exportJson = () => {
    if (!results) return
    const blob = new Blob([JSON.stringify(results, null, 2)], {type:'application/json'})
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `validation-${id}.json`
    a.click()
    URL.revokeObjectURL(url)
    toast.success('JSON export completed')
  }

  if (isLoading) return <div className="p-6 max-w-6xl mx-auto animate-pulse space-y-4"><div className="h-24 bg-muted rounded" /><div className="h-96 bg-muted rounded" /></div>
  if (!results || !overview) return <div className="p-6 max-w-6xl mx-auto"><p className="text-muted-foreground">No validation results are available from the API yet.</p><Link to={`/validations/${id}/progress`} className="text-primary underline text-sm">View Progress</Link></div>

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-4">
      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="px-5 py-4 flex flex-wrap justify-between gap-3 border-b">
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-primary" />
              <span className="font-mono text-sm font-semibold">Validation #{id}</span>
              <span className="px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-xs">COMPLETED ✓</span>
            </div>
            <div className="text-xs text-muted-foreground mt-1 font-mono" dir="ltr">{validationMeta?.target_value || results.assets?.[0]?.name || 'Target unavailable'} • {validationMeta?.created_at ? new Date(validationMeta.created_at).toLocaleString() : ''}</div>
          </div>
          <div className="flex gap-2">
            <button onClick={exportJson} className="px-3 py-1.5 rounded-lg border bg-card text-xs inline-flex items-center gap-1 hover:bg-muted"><Download className="h-3 w-3" /> JSON</button>
            <Link to={`/validations/${id}/progress`} className="px-3 py-1.5 rounded-lg bg-primary text-primary-foreground text-xs">Progress</Link>
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 px-5 py-4">
          <div className="rounded-lg bg-muted/30 p-3 text-center"><div className="text-2xl font-bold">{overview.risk_score}<span className="text-sm font-normal">/100</span></div><div className="text-xs text-muted-foreground">Risk Score</div></div>
          <div className="rounded-lg bg-muted/30 p-3 text-center"><div className="text-2xl font-bold">{overview.findings_count}</div><div className="text-xs text-muted-foreground">Findings</div></div>
          <div className="rounded-lg bg-muted/30 p-3 text-center"><div className="text-2xl font-bold">{overview.assets_count}</div><div className="text-xs text-muted-foreground">Assets</div></div>
          <div className="rounded-lg bg-muted/30 p-3 text-center"><div className="text-2xl font-bold">{overview.evidence_count}</div><div className="text-xs text-muted-foreground">Evidence</div></div>
        </div>
        <div className="px-5 pb-3 flex gap-2 flex-wrap">
          {Object.entries(overview.severity_counts || {}).map(([k,v])=> (
            <span key={k} className={cn('text-xs px-2 py-0.5 rounded-full font-medium capitalize', sevColor[k] || 'bg-muted')}>{k} {v as number}</span>
          ))}
          <span className="text-xs text-muted-foreground ml-2">Engines {overview.engines_executed} • {overview.validation_summary}</span>
        </div>
      </div>

      <div className="flex gap-1 overflow-auto border-b pb-0">
        {TABS.map(t=> (
          <button key={t.id} onClick={()=>setTab(t.id)} className={cn('px-3 py-2 text-xs font-medium border-b-2 whitespace-nowrap inline-flex items-center gap-1', tab===t.id ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground')}>
            <t.icon className="h-3.5 w-3.5" />{t.label}
          </button>
        ))}
      </div>

      {tab==='overview' && (
        <div className="grid md:grid-cols-2 gap-4">
          <div className="rounded-xl border bg-card p-4">
            <h3 className="text-sm font-semibold mb-3">Severity distribution</h3>
            <div className="space-y-2">
              {Object.entries(overview.severity_counts || {}).map(([sev,count])=> (
                <div key={sev} className="flex items-center gap-2 text-xs">
                  <span className={cn('px-2 py-0.5 rounded text-white text-[11px] capitalize w-24 text-center', sevColor[sev])}>{sev}</span>
                  <div className="flex-1 h-2 rounded bg-muted overflow-hidden"><div className="h-full bg-primary" style={{width:`${overview.findings_count ? (count as number)/overview.findings_count*100 : 0}%`}} /></div>
                  <span className="w-6 text-right">{count as number}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="rounded-xl border bg-card p-4">
            <h3 className="text-sm font-semibold mb-3">Assets</h3>
            <div className="space-y-2">
              {(results.assets || []).map((a:any)=> (
                <div key={a.id} className="rounded-lg border p-2 text-xs">
                  <div className="font-mono font-medium">{a.name} <span className="text-muted-foreground">({a.type}) {a.ip}</span></div>
                  <div className="flex gap-1 mt-1">{(a.services || []).map((s:any)=> <span key={s.port} className="px-1.5 py-0.5 rounded bg-muted font-mono text-[11px]">{s.service}:{s.port}</span>)}</div>
                </div>
              ))}
              {results.assets?.length === 0 && <div className="text-xs text-muted-foreground">No assets returned by the API.</div>}
            </div>
          </div>
        </div>
      )}

      {tab==='findings' && (
        <div className="rounded-xl border bg-card overflow-hidden">
          <div className="p-3 flex flex-wrap gap-2 border-b bg-muted/20">
            <div className="flex gap-1">
              {['','critical','high','medium','low','informational'].map(s=> (
                <button key={s} onClick={()=>setSevFilter(s)} className={cn('px-2 py-1 rounded text-xs capitalize border', sevFilter===s ? 'bg-primary text-primary-foreground border-primary' : 'bg-card')}>{s||'All'}</button>
              ))}
            </div>
            <div className="flex-1" />
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground" />
              <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search finding / asset / category" className="pl-6 pr-3 py-1.5 rounded-lg border bg-background text-xs w-56" />
            </div>
          </div>
          <div className="overflow-auto">
            <table className="w-full text-xs">
              <thead><tr className="border-b bg-muted/20 text-muted-foreground"><th className="text-start px-3 py-2">Severity</th><th className="text-start px-3 py-2">Finding</th><th className="text-start px-3 py-2">Asset</th><th className="text-start px-3 py-2">Confidence</th><th className="text-start px-3 py-2">Status</th></tr></thead>
              <tbody>
                {findings.map((f:any)=> (
                  <tr key={f.id} onClick={()=>setSelectedFinding(f)} className="border-b hover:bg-muted/30 cursor-pointer">
                    <td className="px-3 py-2"><span className={cn('px-2 py-0.5 rounded text-[11px] font-medium', sevColor[f.severity] || 'bg-muted')}>{f.severity}</span></td>
                    <td className="px-3 py-2"><div className="font-medium">{f.title}</div><div className="text-muted-foreground text-[11px]">{f.category} • {f.cwe} • CVSS {f.cvss}</div></td>
                    <td className="px-3 py-2 font-mono">{f.asset || 'Asset unavailable'}</td>
                    <td className="px-3 py-2">{f.confidence != null ? `${f.confidence}%` : 'Confidence unavailable'}</td>
                    <td className="px-3 py-2"><span className={cn('px-1.5 py-0.5 rounded text-[11px] border', f.status==='reviewed' ? 'bg-emerald-50 border-emerald-200 text-emerald-700' : 'bg-amber-50 border-amber-200 text-amber-700')}>{f.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {findings.length===0 && <div className="p-6 text-center text-sm text-muted-foreground">No findings returned by the validation findings API.</div>}
        </div>
      )}

      {tab==='evidence' && (
        <div className="rounded-xl border bg-card p-4 space-y-4">
          <div className="flex gap-2">
            <select value={evidenceFinding} onChange={e=>setEvidenceFinding(e.target.value)} className="px-2 py-1.5 rounded border bg-background text-xs">
              <option value="">All evidence</option>
              {(results.findings || []).map((f:any)=> <option key={f.id} value={f.id}>{f.title} ({f.id})</option>)}
            </select>
            <button onClick={()=>setEvidenceFinding('')} className="px-2 py-1 rounded border text-xs">Clear</button>
            <span className="text-xs text-muted-foreground self-center ml-2">Finding → Evidence → Raw (Monaco) • {evidences.length} items</span>
          </div>
          <EvidenceMonacoViewer evidences={evidences} />
        </div>
      )}

      {tab==='graph' && (
        <div className="rounded-xl border bg-card p-4">
          <h3 className="text-sm font-semibold mb-2">Evidence Graph — Target → Asset → Service → Finding → Evidence → Control</h3>
          <p className="text-xs text-muted-foreground mb-3">Risk → Finding → Evidence → Asset → Control → Remediation without losing context</p>
          <div className="rounded-lg border bg-muted/20 p-4 overflow-auto">
            <div className="flex flex-wrap gap-2 items-center text-xs">
              {graphData ? (
                <>
                  {graphData.graph.nodes.slice(0,18).map((n:any)=> (
                    <span key={n.id} className={cn('px-2 py-1 rounded-full border font-mono text-[11px]', n.type==='target' ? 'bg-primary text-primary-foreground border-primary' : n.type==='finding' ? 'bg-amber-100 border-amber-300 dark:bg-amber-900/30' : n.type==='evidence' ? 'bg-slate-100 border-slate-300 dark:bg-slate-800' : 'bg-card')}>{n.type}:{n.label}</span>
                  ))}
                  <span className="text-muted-foreground">+ {graphData.graph.edges.length} relationships</span>
                </>
              ) : <span className="text-muted-foreground">Loading graph…</span>}
            </div>
            {graphData && (
              <div className="mt-4 grid gap-1 text-[11px] font-mono">
                {graphData.graph.edges.slice(0,14).map((e:any,i:number)=> (
                  <div key={i} className="flex items-center gap-2"><span className="px-1.5 py-0.5 rounded bg-card border">{e.from}</span><ChevronRight className="h-3 w-3 text-muted-foreground" /><span className="text-muted-foreground">{e.label}</span><ChevronRight className="h-3 w-3 text-muted-foreground" /><span className="px-1.5 py-0.5 rounded bg-card border">{e.to}</span></div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {tab==='paths' && (
        <div className="space-y-3">
          {(pathsData?.items || results.attack_paths || []).map((ap:any)=> (
            <div key={ap.id} className="rounded-xl border bg-card p-4">
              <div className="flex items-center justify-between"><span className="font-mono text-xs font-semibold">{ap.id}</span><span className={cn('text-xs px-2 py-0.5 rounded-full', ap.risk==='critical' ? 'bg-red-600 text-white' : 'bg-amber-500 text-white')}>{ap.risk}</span></div>
              <div className="mt-2 flex flex-wrap items-center gap-1 text-xs">
                <span className="px-2 py-1 rounded bg-muted font-mono">{ap.entry}</span><ChevronRight className="h-3 w-3" />
                <span className="px-2 py-1 rounded bg-muted">{ap.discovery}</span><ChevronRight className="h-3 w-3" />
                <span className="px-2 py-1 rounded bg-amber-100 dark:bg-amber-900/30">{ap.weakness}</span><ChevronRight className="h-3 w-3" />
                <span className="px-2 py-1 rounded bg-destructive/10">{ap.impact}</span>
              </div>
              <div className="mt-2 text-[11px] font-mono text-muted-foreground">Chain: {(ap.chain || []).join(' → ')}</div>
            </div>
          ))}
          {!(pathsData?.items || results.attack_paths || []).length && <div className="rounded-xl border bg-card p-6 text-center text-sm text-muted-foreground">No attack paths returned by the validation API.</div>}
        </div>
      )}

      {tab==='controls' && (
        <div className="rounded-xl border bg-card overflow-hidden">
          <table className="w-full text-xs">
            <thead><tr className="border-b bg-muted/20 text-muted-foreground"><th className="text-start px-3 py-2">Control</th><th className="text-start px-3 py-2">Remediation</th><th className="text-start px-3 py-2">Priority</th><th className="text-start px-3 py-2">Verification</th></tr></thead>
            <tbody>
              {(controlsData?.items || results.controls || []).map((c:any)=> (
                <tr key={c.id} className="border-b">
                  <td className="px-3 py-2 font-medium">{c.title}</td>
                  <td className="px-3 py-2 text-muted-foreground">{c.remediation}</td>
                  <td className="px-3 py-2"><span className={cn('px-1.5 py-0.5 rounded text-[11px]', c.priority==='P1' ? 'bg-red-600 text-white' : 'bg-amber-500 text-white')}>{c.priority}</span></td>
                  <td className="px-3 py-2">{c.verification}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!(controlsData?.items || results.controls || []).length && <div className="p-6 text-center text-sm text-muted-foreground">No controls returned by the validation API.</div>}
        </div>
      )}

      {tab==='compliance' && (
        <div className="rounded-xl border bg-card overflow-hidden">
          <table className="w-full text-xs">
            <thead><tr className="border-b bg-muted/20 text-muted-foreground"><th className="text-start px-3 py-2">Framework</th><th className="text-start px-3 py-2">Control</th><th className="text-start px-3 py-2">Status</th></tr></thead>
            <tbody>
              {(complianceData?.items || results.compliance || []).map((c:any,i:number)=> (
                <tr key={i} className="border-b">
                  <td className="px-3 py-2 font-mono">{c.framework}</td>
                  <td className="px-3 py-2">{c.control}</td>
                  <td className="px-3 py-2"><span className={cn('px-2 py-0.5 rounded text-[11px] capitalize', c.status==='fail' ? 'bg-destructive text-destructive-foreground' : c.status==='partial' ? 'bg-amber-500 text-white' : 'bg-emerald-500 text-white')}>{c.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
          {!(complianceData?.items || results.compliance || []).length && <div className="p-6 text-center text-sm text-muted-foreground">No compliance mappings returned by the validation API.</div>}
        </div>
      )}

      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex">
          <div className="flex-1 bg-black/40" onClick={()=>setSelectedFinding(null)} />
          <div className="w-full max-w-xl bg-card border-l overflow-auto p-5 space-y-4">
            <div className="flex justify-between items-start">
              <div><span className={cn('px-2 py-0.5 rounded text-white text-xs', sevColor[selectedFinding.severity] || 'bg-muted')}>{selectedFinding.severity}</span><h2 className="font-semibold mt-2">{selectedFinding.title}</h2><div className="text-xs text-muted-foreground">{selectedFinding.category} • {selectedFinding.cwe} • CVSS {selectedFinding.cvss} • Confidence {selectedFinding.confidence}%</div></div>
              <button onClick={()=>setSelectedFinding(null)} className="p-1 rounded hover:bg-muted">×</button>
            </div>
            <div className="text-xs space-y-2">
              <div><div className="font-medium">Description</div><div className="text-muted-foreground">{selectedFinding.description}</div></div>
              <div><div className="font-medium">Impact</div><div className="text-muted-foreground">{selectedFinding.impact}</div></div>
              <div><div className="font-medium">Affected Asset</div><div className="font-mono">{selectedFinding.asset || 'Asset unavailable'}</div></div>
              <div><div className="font-medium">Evidence ({selectedFinding.evidence_ids?.length || 0})</div><div className="space-y-1 mt-1">{(selectedFinding.evidence_ids || []).map((eid:string)=> <div key={eid} className="rounded border px-2 py-1 font-mono text-[11px] flex justify-between"><span>{eid}</span><button onClick={()=>{navigator.clipboard.writeText(eid); toast.success('Copied')}} className="text-primary">Copy</button></div>)}</div></div>
              <div><div className="font-medium">Attack Path</div><div className="font-mono text-[11px] text-muted-foreground">Target → Asset → Finding → Impact</div></div>
              <div><div className="font-medium">Remediation</div><div className="text-muted-foreground">{(results.controls || []).find((c:any)=>c.finding_ids?.includes(selectedFinding.id))?.remediation || 'See Controls tab'}</div></div>
            </div>
            <button onClick={()=>{setEvidenceFinding(selectedFinding.id); setTab('evidence'); setSelectedFinding(null)}} className="px-3 py-1.5 rounded border text-xs inline-flex items-center gap-1"><Eye className="h-3 w-3" /> View Evidence</button>
          </div>
        </div>
      )}
    </div>
  )
}

const EvidenceMonacoViewer = ({ evidences }: { evidences: any[] }) => {
  const [selected, setSelected] = useState(0)
  const ev = evidences[selected]
  const [viewMode, setViewMode] = useState<'pretty'|'raw'>('pretty')
  if (!ev) return <div className="text-xs text-muted-foreground">No evidence returned by the validation API.</div>
  const content = viewMode==='raw' ? JSON.stringify(ev, null, 2) : JSON.stringify(ev.data, null, 2)
  const lang = ev.type==='request' || ev.type==='response' ? 'json' : 'json'
  return (
    <div className="grid md:grid-cols-3 gap-3">
      <div className="border rounded-lg overflow-hidden md:col-span-1 max-h-[420px] overflow-auto">
        {evidences.slice(0,30).map((e:any,i:number)=> (
          <button key={e.id} onClick={()=>setSelected(i)} className={cn('w-full text-start px-3 py-2 border-b text-xs flex justify-between items-center', i===selected ? 'bg-primary/10 border-primary/20' : 'hover:bg-muted/50')}>
            <span className="font-mono truncate">{e.id}</span>
            <span className="text-[11px] px-1.5 py-0.5 rounded bg-muted capitalize">{e.type}</span>
          </button>
        ))}
      </div>
      <div className="md:col-span-2 border rounded-lg overflow-hidden">
        <div className="px-3 py-2 border-b bg-muted/30 flex items-center justify-between">
          <span className="text-xs font-mono font-medium flex items-center gap-1"><Braces className="h-3 w-3" />{ev.id} • {ev.engine} • {ev.type}</span>
          <div className="flex gap-1">
            <button onClick={()=>setViewMode('pretty')} className={cn('px-2 py-1 rounded text-[11px] border', viewMode==='pretty' ? 'bg-primary text-primary-foreground' : 'bg-card')}>Data</button>
            <button onClick={()=>setViewMode('raw')} className={cn('px-2 py-1 rounded text-[11px] border', viewMode==='raw' ? 'bg-primary text-primary-foreground' : 'bg-card')}>Raw</button>
            <button onClick={()=>{navigator.clipboard.writeText(content); toast.success('Copied')}} className="px-2 py-1 rounded border bg-card text-[11px]">Copy</button>
          </div>
        </div>
        <div className="h-[360px]">
          <Editor height="360px" language={lang} value={content} options={{ readOnly: true, minimap: {enabled:false}, fontSize: 12, scrollBeyondLastLine:false, wordWrap:'on' }} theme="vs-dark" />
        </div>
        {ev.finding_id && <div className="px-3 py-1.5 bg-amber-50 dark:bg-amber-950/20 text-[11px]">Linked Finding: <span className="font-mono">{ev.finding_id}</span> — Finding → Evidence → Control</div>}
      </div>
    </div>
  )
}
