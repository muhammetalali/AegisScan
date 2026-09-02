import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { Activity, AlertTriangle, ArrowRight, Bug, CheckCircle2, Clock3, Download, FileCheck2, Filter, Gauge, Layers3, RefreshCw, Search, ShieldCheck, TrendingDown, XCircle } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { cn } from '@/utils/cn'
import { useLanguageStore } from '@/stores/languageStore'

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'

const severityMeta: Record<Severity, { label: string; badge: string; dot: string }> = {
  critical: { label: 'Critical', badge: 'bg-red-500/10 text-red-600 border-red-500/20 dark:text-red-400', dot: 'bg-red-500' },
  high: { label: 'High', badge: 'bg-orange-500/10 text-orange-600 border-orange-500/20 dark:text-orange-400', dot: 'bg-orange-500' },
  medium: { label: 'Medium', badge: 'bg-amber-500/10 text-amber-700 border-amber-500/20 dark:text-amber-400', dot: 'bg-amber-500' },
  low: { label: 'Low', badge: 'bg-emerald-500/10 text-emerald-700 border-emerald-500/20 dark:text-emerald-400', dot: 'bg-emerald-500' },
  informational: { label: 'Info', badge: 'bg-slate-500/10 text-slate-600 border-slate-500/20 dark:text-slate-400', dot: 'bg-slate-400' },
}

type ResultsData = {
  status?: string | null
  target_value?: string | null
  created_at?: string | null
  overview?: {
    findings_count?: number | null
    risk_score?: number | null
    posture_score?: number | null
    security_posture?: number | null
    assets_count?: number | null
    evidence_count?: number | null
    engines_executed?: number | null
    severity_counts?: Record<string, number | null>
    validation_summary?: string | null
  } | null
  findings?: unknown[]
  assets?: unknown[]
}

type Finding = {
  id?: string
  title?: string
  name?: string
  category?: string
  cwe?: string
  cvss?: number | string | null
  severity?: Severity | string
  asset?: string
  asset_name?: string
  confidence?: number | string | null
  status?: string | null
}

const reportedNumber = (value: unknown): number | null => typeof value === 'number' && Number.isFinite(value) ? value : null
const displayValue = (value: unknown, unavailable = 'Unavailable') => value === null || value === undefined || value === '' ? unavailable : String(value)
const resultArray = (value: unknown): Finding[] => Array.isArray(value) ? value as Finding[] : []

export const ValidationCommandCenter = () => {
  const { id } = useParams<{ id: string }>()
  const t = useLanguageStore(s => s.t)
  const [severity, setSeverity] = useState<'all' | Severity>('all')
  const [query, setQuery] = useState('')

  const resultsQuery = useQuery<ResultsData>({
    queryKey: ['validation-command-center', id],
    queryFn: () => apiHelpers.get<ResultsData>(`/validations/${id}/results`),
    enabled: Boolean(id),
  })

  const findingsQuery = useQuery<{ items?: Finding[]; results?: Finding[] } | Finding[]>({
    queryKey: ['validation-command-center-findings', id, severity, query],
    queryFn: () => {
      const params = new URLSearchParams()
      if (severity !== 'all') params.set('severity', severity)
      if (query.trim()) params.set('q', query.trim())
      const suffix = params.toString() ? `?${params.toString()}` : ''
      return apiHelpers.get(`/validations/${id}/findings${suffix}`)
    },
    enabled: Boolean(id),
  })

  const data = resultsQuery.data
  const overview = data?.overview ?? null
  const findings = useMemo(() => {
    const remote = findingsQuery.data
    return Array.isArray(remote) ? remote : remote?.items ?? remote?.results ?? resultArray(data?.findings)
  }, [findingsQuery.data, data?.findings])

  const status = typeof data?.status === 'string' && data.status.trim() ? data.status.trim().toLowerCase() : null
  const isCompleted = status === 'completed'
  const isFailed = status === 'failed' || status === 'cancelled'
  const totalFindings = reportedNumber(overview?.findings_count)
  const riskScore = reportedNumber(overview?.risk_score)
  const postureScore = reportedNumber(overview?.posture_score ?? overview?.security_posture)
  const assetsCount = reportedNumber(overview?.assets_count)
  const evidenceCount = reportedNumber(overview?.evidence_count)
  const enginesExecuted = reportedNumber(overview?.engines_executed)
  const counts = overview?.severity_counts ?? null

  const distribution = useMemo(() => (Object.keys(severityMeta) as Severity[]).map(key => {
    const count = reportedNumber(counts?.[key])
    const percent = totalFindings !== null && count !== null && totalFindings > 0 ? Math.round((count / totalFindings) * 100) : null
    return { key, count, percent }
  }), [counts, totalFindings])

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

  const statusLabel = status ? status.toUpperCase() : t('Not reported')
  const statusClass = isCompleted ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400' : isFailed ? 'border-red-500/20 bg-red-500/10 text-red-700 dark:text-red-400' : 'border-primary/20 bg-primary/10 text-primary'

  return (
    <div className="mx-auto w-full max-w-[1500px] space-y-5 pb-10">
      <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="enterprise-card relative overflow-hidden rounded-3xl p-5 md:p-7">
        <div className="absolute inset-x-0 top-0 h-1 bg-primary/80" />
        <div className="relative flex flex-col gap-5 xl:flex-row xl:items-center xl:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 text-xs font-medium uppercase tracking-[0.16em] text-primary"><ShieldCheck className="h-4 w-4" /> Validation Command Center <span className="text-muted-foreground">/</span><span className="font-mono normal-case tracking-normal">{id}</span></div>
            <div className="mt-3 flex flex-wrap items-center gap-3"><h1 className="text-2xl font-semibold tracking-tight md:text-3xl">{t('Security Validation Results')}</h1><span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold', statusClass)}>{isCompleted ? <CheckCircle2 className="h-3.5 w-3.5" /> : <Activity className="h-3.5 w-3.5" />}{statusLabel}</span></div>
            <div className="mt-2 flex flex-wrap gap-x-5 gap-y-2 text-xs text-muted-foreground"><span className="inline-flex items-center gap-1.5"><TargetIcon /> <span dir="ltr" className="font-mono text-foreground">{displayValue(data.target_value, t('Unavailable'))}</span></span><span className="inline-flex items-center gap-1.5"><Clock3 className="h-3.5 w-3.5" />{data.created_at ? new Date(data.created_at).toLocaleString() : t('Not reported')}</span><span className="inline-flex items-center gap-1.5"><Layers3 className="h-3.5 w-3.5" />{enginesExecuted === null ? t('Not reported') : enginesExecuted} {t('Engines executed')}</span></div>
          </div>
          <div className="flex flex-wrap gap-2"><button onClick={exportJson} className="inline-flex items-center gap-2 rounded-xl border bg-background px-3.5 py-2.5 text-xs font-medium hover:bg-muted"><Download className="h-4 w-4" /> {t('Export JSON')}</button><Link to={`/validations/${id}/progress`} className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-xs font-semibold text-primary-foreground"><Activity className="h-4 w-4" /> {t('Execution Timeline')}</Link></div>
        </div>
      </motion.section>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <Metric label={t('Security Posture')} value={postureScore === null ? t('Not reported') : `${postureScore}/100`} icon={ShieldCheck} />
        <Metric label={t('Risk Score')} value={riskScore === null ? t('Not reported') : riskScore} icon={Gauge} />
        <Metric label={t('Findings')} value={totalFindings === null ? t('Not reported') : totalFindings} icon={Bug} />
        <Metric label={t('Assets')} value={assetsCount === null ? t('Not reported') : assetsCount} icon={TargetIcon} />
        <Metric label={t('Evidence')} value={evidenceCount === null ? t('Not reported') : evidenceCount} icon={FileCheck2} />
      </section>

      <section className="grid gap-5 xl:grid-cols-[1.1fr_.9fr]">
        <div className="enterprise-card rounded-2xl p-5 md:p-6"><div className="flex items-start justify-between gap-4"><div><p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">{t('Risk intelligence')}</p><h2 className="mt-1 text-lg font-semibold">{t('Finding severity profile')}</h2><p className="mt-1 text-xs text-muted-foreground">{t('Prioritize remediation by impact rather than raw finding volume.')}</p></div><Bug className="h-5 w-5 text-primary" /></div><div className="mt-7 space-y-4">{distribution.map(item => <div key={item.key} className="space-y-1.5"><div className="flex items-center justify-between text-xs"><span className="inline-flex items-center gap-2"><span className={cn('h-2 w-2 rounded-full', severityMeta[item.key].dot)} />{severityMeta[item.key].label}</span><span className="font-semibold">{item.count === null ? t('Not reported') : item.count}{item.percent === null ? null : <span className="ms-1 font-normal text-muted-foreground">{item.percent}%</span>}</span></div><div className="h-2 overflow-hidden rounded-full bg-muted">{item.percent !== null && <motion.div initial={{ width: 0 }} animate={{ width: `${item.percent}%` }} transition={{ duration: .6 }} className={cn('h-full rounded-full', severityMeta[item.key].dot)} />}</div></div>)}</div></div>
        <div className="enterprise-card rounded-2xl p-5 md:p-6"><div className="flex items-start justify-between"><div><p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">{t('Assurance snapshot')}</p><h2 className="mt-1 text-lg font-semibold">{t('Validation coverage')}</h2></div><TrendingDown className="h-5 w-5 text-primary" /></div><div className="mt-6 grid grid-cols-2 gap-3"><Snapshot label={t('Engines executed')} value={enginesExecuted === null ? t('Not reported') : enginesExecuted} /><Snapshot label={t('Validation status')} value={status ? status : t('Not reported')} /><Snapshot label={t('Summary')} value={displayValue(overview?.validation_summary, t('Unavailable'))} wide /></div></div>
      </section>

      <section className="enterprise-card overflow-hidden rounded-2xl"><div className="border-b p-4 md:p-5"><div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between"><div><p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">{t('Risk register')}</p><h2 className="mt-1 text-lg font-semibold">{t('Findings requiring attention')}</h2></div><div className="flex flex-col gap-2 sm:flex-row"><div className="relative"><Search className="absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><input value={query} onChange={e => setQuery(e.target.value)} placeholder={t('Search findings, assets…')} className="h-10 w-full rounded-xl border bg-background ps-9 pe-3 text-xs outline-none focus:ring-2 focus:ring-primary/20 sm:w-64" /></div><div className="flex items-center gap-1 overflow-auto rounded-xl border bg-muted/20 p-1"><Filter className="mx-2 h-3.5 w-3.5 text-muted-foreground" />{(['all', ...Object.keys(severityMeta)] as const).map(item => <button key={item} onClick={() => setSeverity(item as 'all' | Severity)} className={cn('rounded-lg px-2.5 py-1.5 text-[11px] font-medium capitalize whitespace-nowrap', severity === item ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-muted')}>{item === 'all' ? 'All' : severityMeta[item as Severity].label}</button>)}</div></div></div></div><div className="overflow-x-auto"><table className="w-full min-w-[760px] text-xs"><thead><tr className="border-b bg-muted/20 text-start text-muted-foreground"><th className="px-5 py-3 font-medium">Severity</th><th className="px-5 py-3 font-medium">Finding</th><th className="px-5 py-3 font-medium">Asset</th><th className="px-5 py-3 font-medium">Confidence</th><th className="px-5 py-3 font-medium">Status</th><th className="px-5 py-3" /></tr></thead><tbody>{findings.slice(0, 12).map((finding, index) => <FindingRow key={String(finding.id ?? index)} finding={finding as Finding} />)}</tbody></table></div>{findings.length === 0 && <div className="flex flex-col items-center justify-center p-14 text-center"><CheckCircle2 className="h-10 w-10 text-emerald-500" /><h3 className="mt-3 font-semibold">{t('No findings match this view')}</h3><p className="mt-1 text-xs text-muted-foreground">{t('No validation findings were returned by the API.')}</p></div>}</section>
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border bg-muted/20 px-5 py-4 text-xs"><span className="flex items-center gap-2 text-muted-foreground"><CheckCircle2 className="h-4 w-4 text-emerald-500" /> {t('Results are sourced from the validation API and existing AegisScan engines.')}</span><Link to="/reports" className="font-semibold text-primary">{t('Generate a formal report')} <ArrowRight className="ms-1 inline h-3 w-3" /></Link></div>
    </div>
  )
}

const Metric = ({ label, value, icon: Icon }: { label: string; value: string | number; icon: any }) => <div className="enterprise-card rounded-2xl p-4"><div className="flex items-center justify-between"><span className="text-xs text-muted-foreground">{label}</span><Icon className="h-4 w-4 text-primary" /></div><div className="mt-2 text-2xl font-semibold tracking-tight">{value}</div></div>
const Snapshot = ({ label, value, wide }: { label: string; value: string | number; wide?: boolean }) => <div className={cn('rounded-xl border bg-muted/20 p-3', wide && 'col-span-2')}><div className="text-[11px] text-muted-foreground">{label}</div><div className="mt-1 truncate text-sm font-semibold">{value}</div></div>
const FindingRow = ({ finding }: { finding: Finding }) => { const key = String(finding.severity ?? 'informational').toLowerCase() as Severity; const meta = severityMeta[key] ?? severityMeta.informational; return <tr className="border-b last:border-0 hover:bg-muted/20"><td className="px-5 py-3"><span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2 py-1 text-[10px] font-semibold', meta.badge)}><span className={cn('h-1.5 w-1.5 rounded-full', meta.dot)} />{meta.label}</span></td><td className="px-5 py-3"><div className="max-w-[360px] truncate font-medium">{finding.title ?? finding.name ?? 'Untitled finding'}</div><div className="mt-1 text-[10px] text-muted-foreground">{finding.category ?? 'Security finding'}{finding.cwe ? ` • ${finding.cwe}` : ''}{finding.cvss != null ? ` • CVSS ${finding.cvss}` : ''}</div></td><td className="px-5 py-3 font-mono text-[11px]">{finding.asset ?? finding.asset_name ?? 'Unavailable'}</td><td className="px-5 py-3">{finding.confidence == null ? 'Not reported' : `${finding.confidence}%`}</td><td className="px-5 py-3"><span className="rounded-lg border bg-muted/30 px-2 py-1 text-[10px] capitalize">{finding.status ?? 'Not reported'}</span></td><td className="px-5 py-3 text-end"><Link to={`/vulnerabilities/${finding.id}`} className="inline-flex items-center gap-1 font-medium text-primary">Inspect <ArrowRight className="h-3 w-3" /></Link></td></tr> }
const ResultsSkeleton = () => <div className="mx-auto max-w-[1500px] animate-pulse space-y-5"><div className="h-40 rounded-3xl bg-muted" /><div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">{[1,2,3,4,5].map(i => <div key={i} className="h-28 rounded-2xl bg-muted" />)}</div><div className="h-72 rounded-2xl bg-muted" /><div className="h-96 rounded-2xl bg-muted" /></div>
const ErrorState = ({ id, onRetry }: { id?: string; onRetry: () => void }) => <div className="mx-auto flex max-w-xl flex-col items-center justify-center rounded-3xl border bg-card px-6 py-16 text-center"><XCircle className="h-10 w-10 text-destructive" /><h2 className="mt-4 text-lg font-semibold">Results are unavailable</h2><p className="mt-2 text-sm text-muted-foreground">The validation result could not be loaded from the API. No demo or fallback data is shown.</p><div className="mt-5 flex gap-2"><button onClick={onRetry} className="inline-flex items-center gap-2 rounded-xl border px-4 py-2.5 text-xs font-medium hover:bg-muted"><RefreshCw className="h-4 w-4" /> Retry</button>{id && <Link to={`/validations/${id}/progress`} className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-xs font-semibold text-primary-foreground">View execution <ArrowRight className="h-4 w-4" /></Link>}</div></div>
const TargetIcon = () => <Target className="h-3.5 w-3.5" />
