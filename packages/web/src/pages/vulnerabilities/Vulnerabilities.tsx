import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Bug, Search, MoreHorizontal, Eye, Clock, Shield, RefreshCw, AlertCircle } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'

type Finding = {
  id: string
  title?: string
  description?: string
  severity?: string | null
  status?: string | null
  confidence?: number | null
  risk_score?: number | null
  cvss_score?: number | null
  cwe_id?: string | null
  owasp_category?: string | null
  file_path?: string | null
  project?: string | null
  scan?: string | null
  asset?: string | null
  validation_id?: string | null
  engine?: string | null
}

type FindingsResponse = Finding[] | { results?: Finding[]; items?: Finding[]; count?: number }

const unwrap = (data?: FindingsResponse): { items: Finding[]; total: number } => {
  if (Array.isArray(data)) return { items: data, total: data.length }
  const items = data?.results ?? data?.items ?? []
  return { items, total: data?.count ?? items.length }
}

const sevClass: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-amber-500 text-white',
  low: 'bg-emerald-600 text-white',
  informational: 'bg-slate-500 text-white',
}

const severityOrder: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 }

export const Vulnerabilities = () => {
  const [sev, setSev] = useState('')
  const [status, setStatus] = useState('')
  const [q, setQ] = useState('')
  const [sort, setSort] = useState<'severity' | 'confidence'>('severity')

  const query = useQuery<FindingsResponse>({
    queryKey: ['findings-center', sev, status, q],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (sev) params.set('severity', sev)
      if (status) params.set('status', status)
      if (q) params.set('search', q)
      const qs = params.toString() ? `?${params}` : ''
      return apiHelpers.get<FindingsResponse>(`/vulnerabilities/${qs}`)
    },
    staleTime: 10_000,
  })

  const normalized = useMemo(() => unwrap(query.data), [query.data])
  const items = useMemo(() => normalized.items.slice().sort((a, b) => {
    if (sort === 'confidence') return Number(b.confidence ?? 0) - Number(a.confidence ?? 0)
    return (severityOrder[String(b.severity ?? '').toLowerCase()] ?? 0) - (severityOrder[String(a.severity ?? '').toLowerCase()] ?? 0)
  }), [normalized.items, sort])

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2"><Bug className="h-6 w-6 text-primary" /> Findings Center</h1>
        <p className="text-sm text-muted-foreground">Live vulnerabilities from the PostgreSQL-backed Django API. No demo rows are generated.</p>
      </div>

      <div className="rounded-xl border bg-card p-3 space-y-3">
        <div className="flex flex-wrap gap-2 items-center">
          <div className="flex gap-1">
            {['', 'critical', 'high', 'medium', 'low', 'informational'].map((value) => (
              <button key={value} onClick={() => setSev(value)} className={cn('px-2.5 py-1 rounded-full text-xs capitalize border', sev === value ? 'bg-primary text-primary-foreground border-primary' : 'bg-card hover:bg-accent')}>{value || 'All'}</button>
            ))}
          </div>
          <div className="h-6 w-px bg-border mx-1" />
          <div className="flex gap-1">
            {['', 'open', 'confirmed', 'in_progress', 'resolved', 'accepted_risk', 'false_positive'].map((value) => (
              <button key={value} onClick={() => setStatus(value)} className={cn('px-2 py-1 rounded-full text-xs capitalize border', status === value ? 'bg-primary text-primary-foreground' : 'bg-card hover:bg-accent')}>{value ? value.replace('_', ' ') : 'Any status'}</button>
            ))}
          </div>
          <select value={sort} onChange={(event) => setSort(event.target.value as 'severity' | 'confidence')} className="ml-auto px-2 py-1.5 rounded-lg border bg-background text-xs">
            <option value="severity">Sort: Severity</option>
            <option value="confidence">Sort: Confidence</option>
          </select>
        </div>

        <div className="flex gap-2 items-center">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input value={q} onChange={(event) => setQ(event.target.value)} placeholder="Search title, CWE, OWASP, file path..." className="w-full pl-8 pr-3 py-2 rounded-lg border bg-background text-sm" />
          </div>
          <span className="text-xs text-muted-foreground">{normalized.total} findings</span>
        </div>
      </div>

      <div className="rounded-xl border bg-card overflow-hidden">
        {query.isLoading ? (
          <div className="p-12 text-center text-sm text-muted-foreground">Loading live findings…</div>
        ) : query.isError ? (
          <div className="flex flex-col items-center justify-center gap-3 p-12 text-center">
            <div className="rounded-full border border-destructive/20 bg-destructive/10 p-3"><AlertCircle className="h-5 w-5 text-destructive" /></div>
            <div><p className="font-medium">Findings could not be loaded</p><p className="mt-1 text-sm text-muted-foreground">The live vulnerabilities API returned an error.</p></div>
            <button type="button" onClick={() => query.refetch()} className="inline-flex items-center gap-2 rounded-lg border bg-card px-3 py-2 text-sm font-medium hover:bg-accent"><RefreshCw className="h-4 w-4" /> Retry</button>
          </div>
        ) : (
          <div className="overflow-auto">
            <table className="w-full min-w-[1050px] text-sm">
              <thead><tr className="border-b bg-muted/30 text-xs text-muted-foreground">
                <th className="text-start px-3 py-2">Severity</th>
                <th className="text-start px-3 py-2">Finding</th>
                <th className="text-start px-3 py-2">Asset</th>
                <th className="text-start px-3 py-2">Scan</th>
                <th className="text-start px-3 py-2">Confidence</th>
                <th className="text-start px-3 py-2">Status</th>
                <th className="text-start px-3 py-2">Actions</th>
              </tr></thead>
              <tbody>
                {items.length === 0 ? (
                  <tr><td colSpan={7} className="px-4 py-12 text-center"><Bug className="h-6 w-6 mx-auto text-muted-foreground" /><div className="text-sm font-medium mt-2">No findings</div><div className="text-xs text-muted-foreground">Run a real validation to generate findings.</div></td></tr>
                ) : items.map((finding) => {
                  const severity = String(finding.severity ?? 'informational').toLowerCase()
                  const confidence = finding.confidence == null ? null : Number(finding.confidence)
                  return (
                    <tr key={finding.id} className="border-b last:border-0 hover:bg-muted/30">
                      <td className="px-3 py-2"><span className={cn('px-2 py-0.5 rounded text-[11px] font-medium capitalize', sevClass[severity] ?? 'bg-muted')}>{severity}</span></td>
                      <td className="px-3 py-2">
                        <Link to={`/vulnerabilities/${finding.id}`} className="font-medium hover:underline">{finding.title || finding.id}</Link>
                        <div className="text-[11px] text-muted-foreground">{finding.cwe_id || 'No CWE'}{finding.owasp_category ? ` • ${finding.owasp_category}` : ''}{finding.cvss_score != null ? ` • CVSS ${finding.cvss_score}` : ''}</div>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs">{finding.asset || finding.file_path || '—'}</td>
                      <td className="px-3 py-2 font-mono text-xs">{finding.scan || finding.validation_id || '—'}</td>
                      <td className="px-3 py-2">{confidence == null ? '—' : `${Math.round(confidence)}%`}</td>
                      <td className="px-3 py-2"><span className="px-1.5 py-0.5 rounded text-[11px] border capitalize">{String(finding.status ?? 'unknown').replace('_', ' ')}</span></td>
                      <td className="px-3 py-2"><div className="flex gap-1"><Link to={`/vulnerabilities/${finding.id}`} className="p-1.5 rounded hover:bg-accent" title="View"><Eye className="h-4 w-4" /></Link><button className="p-1.5 rounded hover:bg-accent" title="Assign"><Shield className="h-4 w-4" /></button><button className="p-1.5 rounded hover:bg-accent"><MoreHorizontal className="h-4 w-4" /></button></div></td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        <div className="px-3 py-2 border-t bg-muted/20 flex gap-2 text-xs text-muted-foreground"><span className="inline-flex items-center gap-1"><Clock className="h-3 w-3" />Status lifecycle is persisted by the Django vulnerability API.</span><span className="ml-auto">All displayed records are live API data.</span></div>
      </div>
    </div>
  )
}
