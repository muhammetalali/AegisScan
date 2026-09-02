import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { toast } from 'sonner'
import { AlertTriangle, ArrowRight, CheckCircle2, Loader2, Search, ShieldCheck, Target } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'
import { useLanguageStore } from '@/stores/languageStore'

interface Finding {
  id: string
  title: string
  severity: string
  status: string
  confidence: string
  risk_score: number
  asset_id?: string | null
  asset_name?: string | null
  asset_target?: string | null
  source_engine?: string
}

type FindingResponse = Finding[] | { items?: Finding[]; results?: Finding[]; count?: number }

const unwrapFindings = (data: FindingResponse | undefined): Finding[] => {
  if (Array.isArray(data)) return data
  return data?.items ?? data?.results ?? []
}

const severityTone: Record<string, string> = {
  critical: 'border-red-500/30 bg-red-500/8 text-red-600 dark:text-red-400',
  high: 'border-orange-500/30 bg-orange-500/8 text-orange-600 dark:text-orange-400',
  medium: 'border-amber-500/30 bg-amber-500/8 text-amber-700 dark:text-amber-400',
  low: 'border-emerald-500/30 bg-emerald-500/8 text-emerald-700 dark:text-emerald-400',
  informational: 'border-slate-500/30 bg-slate-500/8 text-slate-600 dark:text-slate-400',
}

export const NewValidation = () => {
  const navigate = useNavigate()
  const { t } = useLanguageStore()
  const [selectedFindingId, setSelectedFindingId] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [scope, setScope] = useState('')
  const [query, setQuery] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const findingsQuery = useQuery<FindingResponse>({
    queryKey: ['validation-source-findings'],
    queryFn: () => apiHelpers.get<FindingResponse>('/vulnerabilities?limit=200'),
    staleTime: 10_000,
  })

  const allFindings = useMemo(() => unwrapFindings(findingsQuery.data), [findingsQuery.data])
  const findings = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    return allFindings
      .filter((finding) => ['nmap', 'nuclei'].includes(String(finding.source_engine || '').toLowerCase()))
      .filter((finding) => !['fixed', 'false_positive', 'accepted_risk', 'wont_fix', 'duplicate'].includes(String(finding.status || '').toLowerCase()))
      .filter((finding) => {
        if (!normalized) return true
        return [finding.title, finding.asset_name, finding.asset_target, finding.source_engine, finding.severity].some(value => String(value || '').toLowerCase().includes(normalized))
      })
  }, [allFindings, query])

  const selectedFinding = useMemo(() => allFindings.find(item => item.id === selectedFindingId) || null, [allFindings, selectedFindingId])
  const sourceEngine = String(selectedFinding?.source_engine || '').toLowerCase()
  const targetType = sourceEngine === 'nmap' ? 'ip' : sourceEngine === 'nuclei' ? 'url' : ''
  const targetValue = selectedFinding?.asset_target || ''
  const effectiveScope = scope.trim() || targetValue

  const createValidation = async () => {
    if (!selectedFinding) return toast.error(t('Choose a real finding'))
    if (!['nmap', 'nuclei'].includes(sourceEngine)) return toast.error(t('Finding source engine is not supported for validation'))
    if (!targetValue) return toast.error(t('The selected finding has no linked asset target'))
    if (!authorized) return toast.error(t('Authorization required before execution'))
    if (!effectiveScope) return toast.error(t('Authorized scope is required'))

    setSubmitting(true)
    try {
      const response = await apiHelpers.post<{ id: string; finding_id: string }>('/validations', {
        finding_id: selectedFinding.id,
        target_type: targetType,
        target_value: targetValue,
        profile: 'custom',
        engines: [sourceEngine],
        scope: effectiveScope,
        authorized: true,
        duration_minutes: 60,
        rate_limit: 5,
        extra: { source: 'finding-investigation' },
      })
      if (!response?.id || response.finding_id !== selectedFinding.id) throw new Error(t('Validation service did not return a finding-linked job'))
      toast.success(t('Real validation job created'))
      navigate(`/validations/${response.id}/progress`, { replace: true })
    } catch (error: any) {
      const detail = error?.response?.data?.detail
      toast.error(typeof detail === 'string' ? detail : error?.message || t('Unable to create validation job'))
    } finally {
      setSubmitting(false)
    }
  }

  if (findingsQuery.isLoading) return <div className="mx-auto w-full max-w-6xl space-y-6"><div className="h-32 animate-pulse rounded-3xl bg-muted" /><div className="h-80 animate-pulse rounded-3xl bg-muted" /></div>
  if (findingsQuery.isError) return <div className="mx-auto flex min-h-[420px] w-full max-w-4xl items-center justify-center"><div className="enterprise-card w-full rounded-3xl p-8 text-center"><AlertTriangle className="mx-auto h-10 w-10 text-red-500" /><h1 className="mt-4 text-xl font-semibold">{t('Unable to load findings')}</h1><p className="mt-2 text-sm text-muted-foreground">{t('Real validation requires finding data from the API. No local or demo data is used.')}</p><button onClick={() => findingsQuery.refetch()} className="mt-5 rounded-xl bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground">{t('Retry')}</button></div></div>

  return (
    <div className="mx-auto w-full max-w-6xl space-y-6 pb-10">
      <section className="enterprise-card relative overflow-hidden rounded-[2rem] p-6 md:p-8">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_75%_0%,color-mix(in_srgb,var(--primary)_12%,transparent),transparent_32%)]" />
        <div className="relative"><div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/5 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.18em] text-primary"><ShieldCheck className="h-3.5 w-3.5" /> {t('Real Validation')}</div><h1 className="mt-4 text-3xl font-semibold tracking-tight md:text-4xl">{t('Create an evidence-linked validation')}</h1><p className="mt-2 max-w-3xl text-sm leading-7 text-muted-foreground">{t('Choose a real finding from the database. The validation engine and target are derived from that finding and execution remains server-authorized.')}</p></div>
      </section>

      <section className="enterprise-card rounded-3xl p-5 md:p-7">
        <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between"><div><p className="text-xs font-semibold uppercase tracking-[0.16em] text-primary">{t('Finding source')}</p><h2 className="mt-1 text-xl font-semibold">{t('Choose a real finding')}</h2><p className="mt-1 text-sm text-muted-foreground">{t('The list is sourced only from the vulnerabilities API. No demo results are injected.')}</p></div><div className="relative w-full md:w-80"><Search className="absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><input value={query} onChange={e => setQuery(e.target.value)} placeholder={t('Search findings, assets…')} className="h-10 w-full rounded-xl border bg-background ps-9 pe-3 text-sm outline-none focus:ring-2 focus:ring-primary/20" /></div></div>
        <div className="mt-5 max-h-[430px] space-y-2 overflow-y-auto pe-1">
          {findings.map(finding => <button key={finding.id} type="button" onClick={() => { setSelectedFindingId(finding.id); setScope(finding.asset_target || '') }} className={cn('w-full rounded-2xl border p-4 text-start transition-all', selectedFindingId === finding.id ? 'border-primary bg-primary/5 shadow-[0_12px_35px_color-mix(in_srgb,var(--primary)_12%,transparent)]' : 'border-border/70 hover:-translate-y-0.5 hover:bg-muted/30')}><div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className={cn('rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase', severityTone[finding.severity] || 'border-border bg-muted text-muted-foreground')}>{finding.severity}</span><span className="rounded-full border px-2 py-0.5 text-[10px] font-medium text-muted-foreground">{finding.source_engine}</span><span className="font-mono text-[10px] text-muted-foreground">{finding.id}</span></div><div className="mt-2 truncate text-sm font-semibold">{finding.title}</div><div className="mt-1 truncate text-xs text-muted-foreground">{finding.asset_name || finding.asset_target || t('Asset unavailable')}</div></div><div className="flex items-center gap-2 text-xs text-muted-foreground"><span>{t('Risk')} {finding.risk_score}</span>{selectedFindingId === finding.id && <CheckCircle2 className="h-5 w-5 text-primary" />}</div></div></button>)}
          {!findings.length && <div className="rounded-2xl border border-dashed p-10 text-center text-sm text-muted-foreground">{t('No findings available for real validation with the current data.')}</div>}
        </div>
      </section>

      <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="enterprise-card rounded-3xl p-5 md:p-7">
        <div className="flex items-center gap-2"><p className="text-xs font-semibold uppercase tracking-[0.16em] text-primary">{t('Execution contract')}</p></div>
        {!selectedFinding ? <div className="mt-5 rounded-2xl border border-dashed p-10 text-center"><Target className="mx-auto h-8 w-8 text-muted-foreground" /><h3 className="mt-3 font-semibold">{t('Choose a finding first')}</h3><p className="mt-1 text-sm text-muted-foreground">{t('Execution stays disabled until a real finding is linked to an asset and supported engine.')}</p></div> : <>
          <div className="mt-5 grid gap-3 md:grid-cols-2 lg:grid-cols-4"><Fact label={t('Finding')} value={selectedFinding.id} mono /><Fact label={t('Engine')} value={sourceEngine} /><Fact label={t('Target')} value={targetValue} mono /><Fact label={t('Target type')} value={targetType.toUpperCase()} /></div>
          <div className="mt-5 rounded-2xl border bg-muted/20 p-4"><div className="text-xs font-semibold uppercase tracking-[0.15em] text-muted-foreground">{t('Authorized scope')}</div><input value={scope} onChange={e => setScope(e.target.value)} dir="ltr" className="mt-3 h-11 w-full rounded-xl border bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-primary/20" placeholder={targetValue} /><p className="mt-2 text-[11px] text-muted-foreground">{t('The backend performs server-side scope authorization. The UI cannot bypass it.')}</p></div>
          <label className={cn('mt-5 flex cursor-pointer gap-3 rounded-2xl border p-4 transition', authorized ? 'border-emerald-500/30 bg-emerald-500/5' : 'hover:bg-muted/30')}><input type="checkbox" checked={authorized} onChange={e => setAuthorized(e.target.checked)} className="mt-1" /><span><span className="block text-sm font-semibold">{t('I confirm this target is authorized')}</span><span className="mt-1 block text-xs leading-5 text-muted-foreground">{t('Authorization is persisted with the ValidationRun and the server-side scope check remains mandatory.')}</span></span></label>
          <div className="mt-6 flex flex-col-reverse gap-3 sm:flex-row sm:items-center sm:justify-between"><button type="button" onClick={() => navigate(-1)} className="rounded-xl border px-4 py-2.5 text-sm font-medium hover:bg-muted">{t('Cancel')}</button><button type="button" disabled={submitting || !authorized || !targetValue} onClick={createValidation} className="inline-flex items-center justify-center gap-2 rounded-xl bg-primary px-6 py-3 text-sm font-semibold text-primary-foreground shadow-[0_12px_30px_color-mix(in_srgb,var(--primary)_25%,transparent)] transition hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-50">{submitting ? <><Loader2 className="h-4 w-4 animate-spin" /> {t('Creating job…')}</> : <>{t('Create Validation Job')} <ArrowRight className="h-4 w-4" /></>}</button></div>
        </>}
      </motion.section>
    </div>
  )
}

const Fact = ({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) => <div className="rounded-2xl border bg-muted/20 p-4"><div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">{label}</div><div dir={mono ? 'ltr' : undefined} className={cn('mt-2 truncate text-sm font-semibold', mono && 'font-mono text-[12px]')}>{value}</div></div>
