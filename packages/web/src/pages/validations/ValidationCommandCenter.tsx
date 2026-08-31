import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ArrowRight, Bug, CheckCircle2, Clock3, Download, ExternalLink, Filter, Gauge, RefreshCw, Search, ShieldCheck, Target } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { cn } from '@/utils/cn'

type Finding = {
  id: string
  title: string
  description?: string
  severity?: string
  status?: string
  confidence?: number
  category?: string
  asset?: string
  risk_score?: number
  source_engine?: string
}

type ValidationResults = {
  id: string
  scan_id: string
  status: string
  target_type: string
  target_value: string
  scope: string
  profile: string
  findings: Finding[]
  evidence: Array<Record<string, unknown>>
  error: string | null
  security_score: number
  risk_level: string
  celery_task_id: string | null
}

const severityClass = (severity: string) => {
  const value = severity.toLowerCase()
  if (value === 'critical') return 'border-red-500/20 bg-red-500/10 text-red-600 dark:text-red-400'
  if (value === 'high') return 'border-orange-500/20 bg-orange-500/10 text-orange-600 dark:text-orange-400'
  if (value === 'medium') return 'border-amber-500/20 bg-amber-500/10 text-amber-700 dark:text-amber-400'
  if (value === 'low') return 'border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'
  return 'border-slate-500/20 bg-slate-500/10 text-slate-600 dark:text-slate-400'
}

export const ValidationCommandCenter = () => {
  const { id } = useParams<{ id: string }>()
  const [severity, setSeverity] = useState('all')
  const [query, setQuery] = useState('')

  const resultsQuery = useQuery<ValidationResults>({
    queryKey: ['validation-results', id],
    queryFn: () => apiHelpers.get<ValidationResults>(`/validations/${id}/results`),
    enabled: Boolean(id),
    refetchInterval: (query) => {
      const status = String(query.state.data?.status ?? '')
      return status === 'queued' || status === 'running' ? 3000 : false
    },
  })

  const findingsQuery = useQuery<{ findings: Finding[] }>({
    queryKey: ['validation-findings', id],
    queryFn: () => apiHelpers.get<{ findings: Finding[] }>(`/validations/${id}/findings`),
    enabled: Boolean(id),
    refetchInterval: () => resultsQuery.data?.status === 'queued' || resultsQuery.data?.status === 'running' ? 3000 : false,
  })

  const data = resultsQuery.data
  const findings = findingsQuery.data?.findings ?? data?.findings ?? []
  const filtered = useMemo(() => findings.filter((finding) => {
    const matchesSeverity = severity === 'all' || String(finding.severity ?? '').toLowerCase() === severity
    const needle = query.trim().toLowerCase()
    const matchesQuery = !needle || [finding.title, finding.description, finding.asset, finding.category, finding.source_engine]
      .filter(Boolean).some((value) => String(value).toLowerCase().includes(needle))
    return matchesSeverity && matchesQuery
  }), [findings, query, severity])

  const counts = useMemo(() => findings.reduce<Record<string, number>>((acc, finding) => {
    const key = String(finding.severity ?? 'unknown').toLowerCase()
    acc[key] = (acc[key] ?? 0) + 1
    return acc
  }, {}), [findings])

  const exportJson = () => {
    if (!data) return
    const href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }))
    const anchor = document.createElement('a')
    anchor.href = href
    anchor.download = `aegisscan-validation-${id}.json`
    anchor.click()
    URL.revokeObjectURL(href)
  }

  if (resultsQuery.isLoading) return <div className="mx-auto max-w-6xl p-6 text-sm text-muted-foreground">Loading the persisted validation record…</div>
  if (resultsQuery.isError || !data) return <div className="mx-auto max-w-xl p-6 text-center"><AlertTriangle className="mx-auto h-8 w-8 text-destructive" /><h1 className="mt-3 text-lg font-semibold">Validation results unavailable</h1><p className="mt-2 text-sm text-muted-foreground">No placeholder result is shown because the persisted backend record is unavailable.</p><button type="button" onClick={() => resultsQuery.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-4 w-4" /> Retry</button></div>

  const score = typeof data.security_score === 'number' ? data.security_score : null
  const status = String(data.status || 'unknown').toLowerCase()

  return <div className="mx-auto w-full max-w-6xl space-y-5 pb-10">
    <header className="rounded-2xl border bg-card p-5 shadow-sm">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div><div className="flex flex-wrap items-center gap-2 text-xs font-medium uppercase tracking-[0.14em] text-primary"><ShieldCheck className="h-4 w-4" /> Validation <span className="text-muted-foreground">/</span><span className="font-mono normal-case tracking-normal">{id}</span></div><h1 className="mt-2 text-2xl font-semibold">Persisted validation results</h1><div className="mt-2 flex flex-wrap gap-x-5 gap-y-2 text-xs text-muted-foreground"><span className="inline-flex items-center gap-1.5"><Target className="h-3.5 w-3.5" /><span dir="ltr" className="font-mono text-foreground">{data.target_value}</span></span><span className="inline-flex items-center gap-1.5"><Clock3 className="h-3.5 w-3.5" />{status}</span><span className="font-mono">Celery: {data.celery_task_id || 'not recorded'}</span></div></div>
        <div className="flex gap-2"><button type="button" onClick={exportJson} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs hover:bg-muted"><Download className="h-4 w-4" /> Export JSON</button><Link to={`/validations/${id}/progress`} className="inline-flex items-center gap-2 rounded-lg bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground">Timeline <ArrowRight className="h-4 w-4" /></Link></div>
      </div>
    </header>

    {data.error && <div className="rounded-xl border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">{data.error}</div>}

    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <Metric title="Security score" value={score === null ? 'Unavailable' : `${score}/100`} icon={ShieldCheck} />
      <Metric title="Risk level" value={data.risk_level || 'Unavailable'} icon={Gauge} />
      <Metric title="Findings" value={String(findings.length)} icon={Bug} />
      <Metric title="Evidence" value={String(data.evidence.length)} icon={CheckCircle2} />
    </div>

    <section className="rounded-2xl border bg-card p-5 shadow-sm">
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"><div><h2 className="text-lg font-semibold">Real findings</h2><p className="text-xs text-muted-foreground">Only findings persisted for this validation are shown.</p></div><div className="flex items-center gap-1 overflow-auto rounded-lg border bg-muted/20 p-1"><Filter className="mx-2 h-3.5 w-3.5 text-muted-foreground" />{['all','critical','high','medium','low','informational'].map((item) => <button key={item} type="button" onClick={() => setSeverity(item === 'informational' ? 'info' : item)} className={cn('rounded-md px-2 py-1.5 text-[11px] font-medium capitalize', severity === (item === 'informational' ? 'info' : item) ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-muted')}>{item}</button>)}</div></div>
      <div className="relative mt-4"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search persisted findings" className="h-10 w-full rounded-lg border bg-background pl-9 pr-3 text-xs" /></div>
      <div className="mt-4 overflow-x-auto"><table className="w-full min-w-[760px] text-xs"><thead><tr className="border-b text-left text-muted-foreground"><th className="px-3 py-3">Severity</th><th className="px-3 py-3">Finding</th><th className="px-3 py-3">Asset</th><th className="px-3 py-3">Confidence</th><th className="px-3 py-3">Status</th><th className="px-3 py-3" /></tr></thead><tbody>{filtered.map((finding) => { const sev = String(finding.severity ?? 'unknown').toLowerCase(); return <tr key={finding.id} className="border-b hover:bg-muted/20"><td className="px-3 py-3"><span className={cn('rounded-full border px-2 py-1 text-[10px] font-semibold', severityClass(sev))}>{sev}</span></td><td className="px-3 py-3"><div className="font-medium">{finding.title}</div><div className="mt-1 text-[11px] text-muted-foreground">{finding.category || '—'} · {finding.source_engine || '—'}</div></td><td className="px-3 py-3 font-mono">{finding.asset || '—'}</td><td className="px-3 py-3">{typeof finding.confidence === 'number' ? `${finding.confidence}%` : '—'}</td><td className="px-3 py-3">{finding.status || '—'}</td><td className="px-3 py-3"><Link to={`/findings/${finding.id}`} className="inline-flex items-center gap-1 text-primary hover:underline">Open <ExternalLink className="h-3 w-3" /></Link></td></tr> })}</tbody></table></div>
      {!filtered.length && <div className="p-8 text-center text-sm text-muted-foreground">No persisted findings match the selected view.</div>}
    </section>

    <section className="rounded-2xl border bg-card p-5 shadow-sm"><div className="flex items-center justify-between"><div><h2 className="text-lg font-semibold">Persisted evidence</h2><p className="text-xs text-muted-foreground">Evidence records linked to this validation in PostgreSQL.</p></div><span className="text-xs text-muted-foreground">{data.evidence.length} records</span></div><div className="mt-4 space-y-2">{data.evidence.map((item, index) => <div key={String(item.id ?? index)} className="rounded-xl border p-3 text-xs"><div className="flex flex-wrap gap-3 font-mono"><span>id={String(item.id ?? '—')}</span><span>source={String(item.source ?? '—')}</span><span>type={String(item.type ?? '—')}</span><span>quality={String(item.quality ?? '—')}</span></div><p className="mt-2 text-muted-foreground">{String(item.description ?? '')}</p></div>)}{!data.evidence.length && <div className="rounded-xl border border-dashed p-8 text-center text-sm text-muted-foreground">No evidence records were persisted.</div>}</div></section>

    <div className="rounded-xl border bg-muted/20 p-4 text-xs text-muted-foreground">Severity counts: {Object.entries(counts).map(([key, value]) => `${key}=${value}`).join(' · ') || 'none'}</div>
  </div>
}

const Metric = ({ title, value, icon: Icon }: { title: string; value: string; icon: any }) => <div className="rounded-2xl border bg-card p-4 shadow-sm"><div className="flex items-center justify-between"><span className="text-xs text-muted-foreground">{title}</span><Icon className="h-4 w-4 text-primary" /></div><div className="mt-2 text-2xl font-semibold tracking-tight capitalize">{value}</div></div>
