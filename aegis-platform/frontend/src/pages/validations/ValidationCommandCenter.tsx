import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { Activity, AlertTriangle, ArrowRight, Bug, CheckCircle2, Clock3, Download, FileCheck2, Filter, Gauge, Layers3, RefreshCw, Search, ShieldCheck, Target, TrendingDown, TrendingUp, XCircle } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { cn } from '@/utils/cn'

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'

const severityMeta: Record<Severity, { label: string; badge: string; dot: string }> = {
  critical: { label: 'Critical', badge: 'bg-red-500/10 text-red-600 border-red-500/20 dark:text-red-400', dot: 'bg-red-500' },
  high: { label: 'High', badge: 'bg-orange-500/10 text-orange-600 border-orange-500/20 dark:text-orange-400', dot: 'bg-orange-500' },
  medium: { label: 'Medium', badge: 'bg-amber-500/10 text-amber-700 border-amber-500/20 dark:text-amber-400', dot: 'bg-amber-500' },
  low: { label: 'Low', badge: 'bg-emerald-500/10 text-emerald-700 border-emerald-500/20 dark:text-emerald-400', dot: 'bg-emerald-500' },
  informational: { label: 'Info', badge: 'bg-slate-500/10 text-slate-600 border-slate-500/20 dark:text-slate-400', dot: 'bg-slate-400' },
}

const safeNumber = (value: unknown, fallback = 0) => typeof value === 'number' && Number.isFinite(value) ? value : fallback

export const ValidationCommandCenter = () => {
  const { id } = useParams<{ id: string }>()
  const [severity, setSeverity] = useState<'all' | Severity>('all')
  const [query, setQuery] = useState('')

  const resultsQuery = useQuery({
    queryKey: ['validation-command-center', id],
    queryFn: () => apiHelpers.get<any>(`/validations/${id}/results`),
    enabled: Boolean(id),
  })

  const findingsQuery = useQuery({
    queryKey: ['validation-command-center-findings', id, severity, query],
    queryFn: () => {
      const params = new URLSearchParams()
      if (severity !== 'all') params.set('severity', severity)
      if (query.trim()) params.set('q', query.trim())
      const suffix = params.toString() ? `?${params.toString()}` : ''
      return apiHelpers.get<any>(`/validations/${id}/findings${suffix}`)
    },
    enabled: Boolean(id),
  })

  const data = resultsQuery.data
  const overview = data?.overview
  const findings = findingsQuery.data?.items ?? data?.findings ?? []
  const counts = (overview?.severity_counts ?? {}) as Record<string, number>
  const totalFindings = safeNumber(overview?.findings_count, findings.length)
  const riskScore = safeNumber(overview?.risk_score)
  const postureScore = Math.max(0, 100 - riskScore)

  const distribution = useMemo(() => (Object.keys(severityMeta) as Severity[]).map(key => ({
    key,
    count: safeNumber(counts[key]),
    percent: totalFindings ? Math.round((safeNumber(counts[key]) / totalFindings) * 100) : 0,
  })), [counts, totalFindings])

  const exportJson = () => {
    if (!data) return
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const href = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = href
    anchor.download = `aegisscan-validation-${id}.json`
    anchor.click()
    URL.revokeObjectURL(href)
  }

  if (resultsQuery.isLoading) return <ResultsSkeleton />
  if (resultsQuery.isError || !data) return <ErrorState id={id} onRetry={() => resultsQuery.refetch()} />

  const status = String(data.status ?? 'completed').toLowerCase()
  const completed = status === 'completed' || !data.status

  return (
    <div className="mx-auto w-full max-w-[1500px] space-y-5 pb-10">
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="relative overflow-hidden rounded-3xl border bg-card shadow-sm">
        <div className="absolute inset-x-0 top-0 h-1 bg-primary/80" />
        <div className="p-5 md:p-7">
          <div className="flex flex-col gap-5 xl:flex-row xl:items-center xl:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2 text-xs font-medium uppercase tracking-[0.16em] text-primary">
                <ShieldCheck className="h-4 w-4" /> Validation Command Center
                <span className="text-muted-foreground">/</span><span className="font-mono normal-case tracking-normal">{id}</span>
              </div>
              <div className="mt-3 flex flex-wrap items-center gap-3">
                <h1 className="text-2xl font-semibold tracking-tight md:text-3xl">Security Validation Results</h1>
                <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold', completed ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400' : 'border-amber-500/20 bg-amber-500/10 text-amber-700')}>
                  {completed ? <CheckCircle2 className="h-3.5 w-3.5" /> : <Activity className="h-3.5 w-3.5 animate-pulse" />}{status.toUpperCase()}
                </span>
              </div>
              <div className="mt-2 flex flex-wrap gap-x-5 gap-y-2 text-xs text-muted-foreground">
                <span className="inline-flex items-center gap-1.5"><Target className="h-3.5 w-3.5" /><span dir="ltr" className="font-mono text-foreground">{data.target_value ?? data.assets?.[0]?.name ?? 'â€”'}</span></span>
                <span className="inline-flex items-center gap-1.5"><Clock3 className="h-3.5 w-3.5" />{data.created_at ? new Date(data.created_at).toLocaleString() : 'Timestamp unavailable'}</span>
                <span className="inline-flex items-center gap-1.5"><Layers3 className="h-3.5 w-3.5" />{safeNumber(overview?.engines_executed)} engines executed</span>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <button onClick={exportJson} className="inline-flex items-center gap-2 rounded-xl border bg-background px-3.5 py-2.5 text-xs font-medium hover:bg-muted"><Download className="h-4 w-4" /> Export JSON</button>
              <Link to={`/validations/${id}/progress`} className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-xs font-semibold text-primary-foreground shadow-sm hover:opacity-90"><Activity className="h-4 w-4" /> Execution Timeline</Link>
            </div>
          </div>
        </div>
      </motion.div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <ScoreCard label="Security Posture" value={postureScore} suffix="/100" icon={ShieldCheck} trend={postureScore >= 70 ? 'Healthy posture' : 'Attention required'} positive={postureScore >= 70} />
        <MetricCard label="Risk Score" value={riskScore} icon={Gauge} tone={riskScore >= 70 ? 'danger' : riskScore >= 40 ? 'warning' : 'success'} />
        <MetricCard label="Findings" value={totalFindings} icon={Bug} tone={totalFindings ? 'warning' : 'success'} />
        <MetricCard label="Assets" value={safeNumber(overview?.assets_count, data.assets?.length)} icon={Target} tone="neutral" />
        <MetricCard label="Evidence" value={safeNumber(overview?.evidence_count, 0)} icon={FileCheck2} tone="neutral" />
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.1fr_.9fr]">
        <section className="rounded-2xl border bg-card p-5 shadow-sm md:p-6">
          <div className="flex items-start justify-between gap-4"><div><p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">Risk intelligence</p><h2 className="mt-1 text-lg font-semibold">Finding severity profile</h2><p className="mt-1 text-xs text-muted-foreground">Prioritize remediation by impact rather than raw finding volume.</p></div><div className="rounded-xl bg-muted/40 p-2.5"><Bug className="h-5 w-5 text-muted-foreground" /></div></div>
          <div className="mt-7 space-y-4">
            {distribution.map(item => <div key={item.key} className="space-y-1.5"><div className="flex items-center justify-between text-xs"><span className="inline-flex items-center gap-2"><span className={cn('h-2 w-2 rounded-full', severityMeta[item.key].dot)} />{severityMeta[item.key].label}</span><span className="font-semibold">{item.count}<span className="ml-1 font-normal text-muted-foreground">{item.percent}%</span></span></div><div className="h-2 overflow-hidden rounded-full bg-muted"><motion.div initial={{ width: 0 }} animate={{ width: `${item.percent}%` }} transition={{ duration: .7 }} className={cn('h-full rounded-full', severityMeta[item.key].dot)} /></div></div>)}
          </div>
        </section>

        <section className="rounded-2xl border bg-card p-5 shadow-sm md:p-6">
          <div className="flex items-start justify-between"><div><p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">Assurance snapshot</p><h2 className="mt-1 text-lg font-semibold">Validation coverage</h2></div><TrendingDown className="h-5 w-5 text-emerald-500" /></div>
          <div className="mt-6 grid grid-cols-2 gap-3">
            <Snapshot label="Engines executed" value={safeNumber(overview?.engines_executed)} />
            <Snapshot label="Validation status" value={completed ? 'Complete' : status} />
            <Snapshot label="Summary" value={String(overview?.validation_summary ?? 'Available')} wide />
          </div>
          <div className="mt-4 rounded-xl border bg-muted/20 p-4"><div className="flex items-center justify-between text-xs"><span className="text-muted-foreground">Posture signal</span><span className="font-semibold">{postureScore >= 70 ? 'Healthy' : 'Needs review'}</span></div><div className="mt-2 h-2 rounded-full bg-muted"><div className="h-full rounded-full bg-primary" style={{ width: `${postureScore}%` }} /></div></div>
        </section>
      </div>

      <section className="overflow-hidden rounded-2xl border bg-card shadow-sm">
        <div className="border-b p-4 md:p-5"><div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between"><div><p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">Risk register</p><h2 className="mt-1 text-lg font-semibold">Findings requiring attention</h2></div><div className="flex flex-col gap-2 sm:flex-row"><div className="relative"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search findings, assetsâ€¦" className="h-10 w-full rounded-xl border bg-background pl-9 pr-3 text-xs outline-none focus:ring-2 focus:ring-primary/20 sm:w-64" /></div><div className="flex items-center gap-1 overflow-auto rounded-xl border bg-muted/20 p-1"><Filter className="mx-2 h-3.5 w-3.5 text-muted-foreground" />{(['all', ...Object.keys(severityMeta)] as const).map(item => <button key={item} onClick={() => setSeverity(item as any)} className={cn('rounded-lg px-2.5 py-1.5 text-[11px] font-medium capitalize whitespace-nowrap', severity === item ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-muted')}>{item === 'all' ? 'All' : severityMeta[item as Severity].label}</button>)}</div></div></div></div>
        <div className="overflow-x-auto"><table className="w-full min-w-[760px] text-xs"><thead><tr className="border-b bg-muted/20 text-left text-muted-foreground"><th className="px-5 py-3 font-medium">Severity</th><th className="px-5 py-3 font-medium">Finding</th><th className="px-5 py-3 font-medium">Asset</th><th className="px-5 py-3 font-medium">Confidence</th><th className="px-5 py-3 font-medium">Status</th><th className="px-5 py-3" /></tr></thead><tbody>{findings.slice(0, 12).map((finding: any) => <FindingRow key={finding.id} finding={finding} />)}</tbody></table></div>
        {findings.length === 0 && <div className="flex flex-col items-center justify-center px-6 py-14 text-center"><CheckCircle2 className="h-10 w-10 text-emerald-500" /><h3 className="mt-3 font-semibold">No findings match this view</h3><p className="mt-1 text-xs text-muted-foreground">Try another severity or search term.</p></div>}
        {findings.length > 12 && <div className="flex items-center justify-between border-t px-5 py-3 text-xs text-muted-foreground"><span>Showing 12 of {findings.length} findings</span><Link to="/vulnerabilities" className="font-medium text-primary hover:underline">Open Findings Center <ArrowRight className="ml-1 inline h-3 w-3" /></Link></div>}
      </section>

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border bg-muted/20 px-5 py-4 text-xs"><div className="flex items-center gap-2 text-muted-foreground"><CheckCircle2 className="h-4 w-4 text-emerald-500" /> Results are sourced from the validation API and existing AegisScan engines.</div><Link to="/reports" className="font-semibold text-primary hover:underline">Generate a formal report <ArrowRight className="ml-1 inline h-3 w-3" /></Link></div>
    </div>
  )
}

const ScoreCard = ({ label, value, suffix, icon: Icon, trend, positive }: any) => <div className="relative overflow-hidden rounded-2xl border bg-card p-4 shadow-sm"><div className="flex items-center justify-between"><span className="text-xs text-muted-foreground">{label}</span><Icon className="h-4 w-4 text-primary" /></div><div className="mt-2 text-3xl font-semibold tracking-tight">{value}<span className="ml-1 text-sm font-normal text-muted-foreground">{suffix}</span></div><div className={cn('mt-1 flex items-center gap-1 text-[11px]', positive ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600')} >{positive ? <TrendingUp className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />}{trend}</div></div>
const MetricCard = ({ label, value, icon: Icon, tone }: any) => <div className="rounded-2xl border bg-card p-4 shadow-sm"><div className="flex items-center justify-between"><span className="text-xs text-muted-foreground">{label}</span><Icon className={cn('h-4 w-4', tone === 'danger' ? 'text-red-500' : tone === 'warning' ? 'text-amber-500' : tone === 'success' ? 'text-emerald-500' : 'text-muted-foreground')} /></div><div className="mt-2 text-2xl font-semibold tracking-tight">{value}</div><div className="mt-1 text-[11px] text-muted-foreground">Live validation metric</div></div>
const Snapshot = ({ label, value, wide }: any) => <div className={cn('rounded-xl border bg-muted/20 p-3', wide && 'col-span-2')}><div className="text-[11px] text-muted-foreground">{label}</div><div className="mt-1 truncate text-sm font-semibold">{value}</div></div>
const FindingRow = ({ finding }: { finding: any }) => { const key = (String(finding.severity ?? 'informational').toLowerCase() in severityMeta ? String(finding.severity).toLowerCase() : 'informational') as Severity; return <tr className="border-b last:border-0 hover:bg-muted/20"><td className="px-5 py-3"><span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2 py-1 text-[10px] font-semibold', severityMeta[key].badge)}><span className={cn('h-1.5 w-1.5 rounded-full', severityMeta[key].dot)} />{severityMeta[key].label}</span></td><td className="px-5 py-3"><div className="max-w-[360px] truncate font-medium">{finding.title ?? finding.name ?? 'Untitled finding'}</div><div className="mt-1 text-[10px] text-muted-foreground">{finding.category ?? 'Security finding'}{finding.cwe ? ` â€¢ ${finding.cwe}` : ''}{finding.cvss ? ` â€¢ CVSS ${finding.cvss}` : ''}</div></td><td className="px-5 py-3 font-mono text-[11px]">{finding.asset ?? finding.asset_name ?? 'â€”'}</td><td className="px-5 py-3">{finding.confidence != null ? `${finding.confidence}%` : 'â€”'}</td><td className="px-5 py-3"><span className="rounded-lg border bg-muted/30 px-2 py-1 text-[10px] capitalize">{finding.status ?? 'open'}</span></td><td className="px-5 py-3 text-right"><Link to={`/vulnerabilities/${finding.id}`} className="inline-flex items-center gap-1 font-medium text-primary hover:underline">Inspect <ArrowRight className="h-3 w-3" /></Link></td></tr> }
const ResultsSkeleton = () => <div className="mx-auto max-w-[1500px] animate-pulse space-y-5"><div className="h-40 rounded-3xl bg-muted" /><div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">{[1,2,3,4,5].map(i => <div key={i} className="h-28 rounded-2xl bg-muted" />)}</div><div className="h-72 rounded-2xl bg-muted" /><div className="h-96 rounded-2xl bg-muted" /></div>
const ErrorState = ({ id, onRetry }: { id?: string; onRetry: () => void }) => <div className="mx-auto flex max-w-xl flex-col items-center justify-center rounded-3xl border bg-card px-6 py-16 text-center"><XCircle className="h-10 w-10 text-destructive" /><h2 className="mt-4 text-lg font-semibold">Results are unavailable</h2><p className="mt-2 text-sm text-muted-foreground">The validation result could not be loaded from the API. No demo or fallback data is shown.</p><div className="mt-5 flex gap-2"><button onClick={onRetry} className="inline-flex items-center gap-2 rounded-xl border px-4 py-2.5 text-xs font-medium hover:bg-muted"><RefreshCw className="h-4 w-4" /> Retry</button><Link to={`/validations/${id}/progress`} className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-xs font-semibold text-primary-foreground">View execution <ArrowRight className="h-4 w-4" /></Link></div></div>
