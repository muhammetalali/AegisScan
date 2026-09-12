import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { AlertTriangle, ArrowLeft, ArrowRight, Check, CheckCircle2, Loader2, Search, ShieldCheck, SlidersHorizontal, Target, Zap } from 'lucide-react'
import { toast } from 'sonner'
import { apiHelpers } from '@/services/api'
import { cn } from '@/utils/cn'
import { useLanguageStore } from '@/stores/languageStore'

type Finding = {
  id: string
  title: string
  description?: string | null
  severity: string
  status: string
  confidence?: number | null
  risk_score?: number | null
  asset_id?: string | null
  asset_name?: string | null
  asset_target?: string | null
  source_engine?: string | null
}
type FindingResponse = Finding[] | { items?: Finding[]; results?: Finding[]; count?: number }
type Profile = 'quick' | 'full' | 'custom'
const unwrap = (data?: FindingResponse) => Array.isArray(data) ? data : data?.items ?? data?.results ?? []
const profiles: Array<{ id: Profile; name: string; description: string; icon: typeof Zap }> = [
  { id: 'quick', name: 'Quick Assessment', description: 'Fast signal with the core assurance path.', icon: Zap },
  { id: 'full', name: 'Full Validation', description: 'Deep validation profile while preserving the selected finding engine contract.', icon: ShieldCheck },
  { id: 'custom', name: 'Custom Profile', description: 'Advanced execution profile with the finding engine kept authoritative.', icon: SlidersHorizontal },
]
const orchestration = ['recon','evidence_collection','vuln_intelligence','validation','control_validation','coverage_gap','attack_path','evidence_graph','knowledge','posture','policy_compliance','twin_engine','scenarios','dashboard','reporting']

export const NewValidation = () => {
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const t = useLanguageStore(s => s.t)
  const requestedFindingId = params.get('finding_id') || ''
  const [step, setStep] = useState(1)
  const [selectedFindingId, setSelectedFindingId] = useState(requestedFindingId)
  const [profile, setProfile] = useState<Profile>('full')
  const [scope, setScope] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [includeSubdomains, setIncludeSubdomains] = useState(false)
  const [queryText, setQueryText] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const findingsQuery = useQuery<FindingResponse>({
    queryKey: ['validation-source-findings', queryText],
    queryFn: () => apiHelpers.get(`/vulnerabilities/?limit=200&offset=0${queryText.trim() ? `&search=${encodeURIComponent(queryText.trim())}` : ''}`),
    staleTime: 10_000,
  })
  const allFindings = useMemo(() => unwrap(findingsQuery.data), [findingsQuery.data])
  const findings = useMemo(() => allFindings.filter(f => ['nmap','nuclei'].includes(String(f.source_engine || '').toLowerCase())).filter(f => !['fixed','false_positive','accepted_risk','wont_fix','duplicate'].includes(String(f.status || '').toLowerCase())), [allFindings])
  const selectedFinding = useMemo(() => allFindings.find(f => f.id === selectedFindingId) ?? null, [allFindings, selectedFindingId])
  const sourceEngine = String(selectedFinding?.source_engine || '').toLowerCase()
  const targetValue = selectedFinding?.asset_target || ''
  const targetType = sourceEngine === 'nmap' ? 'ip' : sourceEngine === 'nuclei' ? 'url' : ''
  const effectiveScope = scope.trim() || targetValue

  useEffect(() => {
    if (requestedFindingId && !selectedFindingId) setSelectedFindingId(requestedFindingId)
  }, [requestedFindingId, selectedFindingId])
  useEffect(() => {
    if (selectedFinding && !scope) setScope(selectedFinding.asset_target || '')
  }, [selectedFinding, scope])

  const canContinue = step === 1 ? Boolean(selectedFinding) : step === 2 ? Boolean(profile) : step === 3 ? Boolean(effectiveScope && authorized) : Boolean(selectedFinding && sourceEngine && targetValue && effectiveScope && authorized)
  const submit = async () => {
    if (!selectedFinding || !['nmap','nuclei'].includes(sourceEngine) || !targetValue || !effectiveScope || !authorized) return toast.error(t('Execution contract is incomplete.'))
    setSubmitting(true)
    try {
      const response = await apiHelpers.post<{ id: string; finding_id: string }>('/validations', {
        finding_id: selectedFinding.id,
        target_type: targetType,
        target_value: targetValue,
        profile,
        engines: [sourceEngine],
        scope: effectiveScope,
        authorized: true,
        include_subdomains: includeSubdomains,
        duration_minutes: 60,
        rate_limit: 5,
        extra: { source: 'finding-investigation', profile_confirmed: true, orchestration_view: orchestration },
      })
      if (!response?.id || response.finding_id !== selectedFinding.id) throw new Error(t('Validation service did not return a finding-linked job'))
      toast.success(t('Real validation job created'))
      navigate(`/validations/${response.id}/progress`, { replace: true })
    } catch (error: any) {
      const detail = error?.response?.data?.detail
      toast.error(typeof detail === 'string' ? detail : error?.message || t('Unable to create validation job'))
    } finally { setSubmitting(false) }
  }

  if (findingsQuery.isLoading) return <div className="mx-auto max-w-6xl space-y-5"><div className="h-32 animate-pulse rounded-3xl bg-muted"/><div className="h-96 animate-pulse rounded-3xl bg-muted"/></div>
  if (findingsQuery.isError) return <div className="mx-auto flex min-h-[440px] max-w-3xl items-center"><div className="enterprise-card w-full rounded-3xl p-10 text-center"><AlertTriangle className="mx-auto h-10 w-10 text-destructive"/><h1 className="mt-4 text-xl font-semibold">{t('Unable to load findings')}</h1><p className="mt-2 text-sm text-muted-foreground">{t('Real validation requires finding data from the API. No local or demo data is used.')}</p><button type="button" onClick={() => findingsQuery.refetch()} className="mt-5 rounded-xl bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground">{t('Retry')}</button></div></div>

  return <div className="mx-auto w-full max-w-6xl space-y-6 pb-10">
    <section className="enterprise-card relative overflow-hidden rounded-[2rem] p-6 md:p-8"><div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_75%_0%,color-mix(in_srgb,var(--primary)_12%,transparent),transparent_32%)]"/><div className="relative"><div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/5 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.18em] text-primary"><ShieldCheck className="h-3.5 w-3.5"/>{t('Real Validation')}</div><h1 className="mt-4 text-3xl font-semibold tracking-tight md:text-4xl">{t('Create an evidence-linked validation')}</h1><p className="mt-2 max-w-3xl text-sm leading-7 text-muted-foreground">{t('Choose a real finding from the database. The validation engine and target are derived from that finding and execution remains server-authorized.')}</p></div></section>
    <section className="enterprise-card rounded-3xl p-3 md:p-4"><div className="grid grid-cols-2 gap-2 md:grid-cols-4">{['Finding source','Profile','Scope & safety','Review'].map((label, i) => { const n=i+1; const active=n===step; const done=n<step; return <button key={label} type="button" onClick={() => done && setStep(n)} className={cn('flex items-center gap-3 rounded-2xl px-4 py-3 text-start transition', active && 'bg-primary/10', done && 'hover:bg-muted')}><span className={cn('grid h-8 w-8 shrink-0 place-items-center rounded-full border text-xs font-semibold', done ? 'border-primary bg-primary text-primary-foreground' : active ? 'border-primary text-primary' : 'border-border text-muted-foreground')}>{done ? <Check className="h-4 w-4"/> : n}</span><span className="text-sm font-medium">{label}</span></button>})}</div></section>

    <motion.section key={step} initial={{ opacity:0, y:8 }} animate={{ opacity:1, y:0 }} className="enterprise-card rounded-3xl p-5 md:p-7">
      {step===1 && <><Header eyebrow="01 / Finding source" title="Choose a real finding" description="Search the authoritative vulnerabilities API. The validation request cannot be created from an unlinked or synthetic finding."/><div className="mt-6 flex flex-col gap-3 md:flex-row"><div className="relative flex-1"><Search className="absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"/><input value={queryText} onChange={e=>setQueryText(e.target.value)} placeholder={t('Search findings, assets…')} className="h-11 w-full rounded-xl border bg-background ps-9 pe-3 text-sm outline-none focus:ring-2 focus:ring-primary/20"/></div><div className="rounded-xl border bg-muted/20 px-4 py-3 text-xs text-muted-foreground">{findings.length} {t('supported findings returned')}</div></div><div className="mt-5 max-h-[430px] space-y-2 overflow-y-auto">{findings.map(f=><button key={f.id} type="button" onClick={()=>{setSelectedFindingId(f.id);setScope(f.asset_target||'')}} className={cn('w-full rounded-2xl border p-4 text-start transition-all',selectedFindingId===f.id?'border-primary bg-primary/5 shadow-lg':'hover:-translate-y-0.5 hover:bg-muted/30')}><div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between"><div><div className="flex flex-wrap items-center gap-2"><span className={cn('rounded-full border px-2 py-1 text-[10px] font-semibold uppercase',severityTone(f.severity))}>{f.severity}</span><span className="rounded-full border px-2 py-1 text-[10px] font-medium text-muted-foreground">{f.source_engine}</span><span className="font-mono text-[10px] text-muted-foreground">{f.id}</span></div><div className="mt-2 text-sm font-semibold">{f.title}</div><div className="mt-1 text-xs text-muted-foreground">{f.asset_name || f.asset_target || t('Asset unavailable')}</div></div>{selectedFindingId===f.id && <CheckCircle2 className="h-5 w-5 text-primary"/>}</div></button>)}{findings.length===0 && <div className="rounded-2xl border border-dashed p-10 text-center text-sm text-muted-foreground">{requestedFindingId && !selectedFinding ? t('Finding not found') : t('No findings available for real validation with the current data.')}</div>}</div></>}
      {step===2 && <><Header eyebrow="02 / Validation profile" title="Preserve the assessment criteria" description="The original quick/full/custom profile controls are restored. The actual validation engine remains locked to the selected finding so the backend contract stays authoritative."/><div className="mt-6 grid gap-3 md:grid-cols-3">{profiles.map(p=>{const Icon=p.icon;return <button key={p.id} type="button" onClick={()=>setProfile(p.id)} className={cn('rounded-2xl border p-5 text-start transition-all',profile===p.id?'border-primary bg-primary/5 shadow-lg':'hover:-translate-y-0.5 hover:bg-muted/30')}><Icon className={cn('h-5 w-5',profile===p.id?'text-primary':'text-muted-foreground')}/><div className="mt-4 font-semibold">{p.name}</div><p className="mt-1 text-xs leading-5 text-muted-foreground">{p.description}</p></button>})}</div><div className="mt-7 rounded-2xl border bg-muted/20 p-5"><div className="flex items-center justify-between"><div><h3 className="font-semibold">Engine orchestration</h3><p className="mt-1 text-xs text-muted-foreground">The capability map is preserved for the assessment architecture; this finding-linked job executes only its authoritative source engine.</p></div><span className="rounded-full border bg-card px-3 py-1 text-xs font-semibold text-primary">{sourceEngine || t('Not selected')}</span></div><div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">{orchestration.map(id=><div key={id} className={cn('rounded-xl border px-3 py-3 text-xs',id===sourceEngine?'border-primary bg-primary/10 text-primary':'bg-background/50 text-muted-foreground')}><div className="font-medium">{id}</div><div className="mt-1 text-[10px]">{id===sourceEngine?'Authoritative for this Finding':'Available assessment capability'}</div></div>)}</div></div></>}
      {step===3 && <><Header eyebrow="03 / Scope & safety" title="Make authorization explicit" description="Scope and authorization are persisted with the real ValidationRun and re-checked server-side."/><div className="mt-6 grid gap-6 lg:grid-cols-[1fr_360px]"><div><div className="grid gap-3 sm:grid-cols-3"><Fact label={t('Finding')} value={selectedFinding?.id || t('Not selected')} mono/><Fact label={t('Engine')} value={sourceEngine || t('Not selected')}/><Fact label={t('Target')} value={targetValue || t('Unavailable')} mono/></div><label className="mt-5 block"><span className="text-sm font-medium">{t('Authorized scope')}</span><textarea value={scope} onChange={e=>setScope(e.target.value)} dir="ltr" rows={7} className="mt-2 w-full resize-none rounded-2xl border bg-background p-4 text-sm outline-none focus:ring-2 focus:ring-primary/20" placeholder={targetValue}/></label><label className="mt-4 flex items-center gap-3 rounded-2xl border p-4"><input type="checkbox" checked={includeSubdomains} onChange={e=>setIncludeSubdomains(e.target.checked)}/><span><span className="block text-sm font-semibold">Include subdomains</span><span className="block text-xs text-muted-foreground">Preserved as an explicit safety option; server scope authorization remains authoritative.</span></span></label></div><div className="rounded-2xl border border-amber-500/25 bg-amber-500/5 p-5"><ShieldCheck className="h-6 w-6 text-amber-500"/><h3 className="mt-4 font-semibold">Authorization required</h3><p className="mt-2 text-xs leading-5 text-muted-foreground">Only assess assets you own or are explicitly authorized to validate.</p><label className={cn('mt-5 flex cursor-pointer gap-3 rounded-xl border p-4',authorized?'border-emerald-500/40 bg-emerald-500/5':'hover:bg-muted/30')}><input type="checkbox" checked={authorized} onChange={e=>setAuthorized(e.target.checked)}/><span className="text-xs font-medium leading-5">I confirm this target is authorized for security validation.</span></label></div></div></>}
      {step===4 && <><Header eyebrow="04 / Review" title="Review the real execution contract" description="Nothing is queued until this review gate is satisfied."/>{!selectedFinding ? <div className="mt-6 rounded-2xl border border-dashed p-10 text-center">{t('Choose a real finding')}</div> : <><div className="mt-6 grid gap-3 md:grid-cols-2 lg:grid-cols-4"><Fact label={t('Finding')} value={selectedFinding.id} mono/><Fact label="Title" value={selectedFinding.title}/><Fact label={t('Engine')} value={sourceEngine}/><Fact label={t('Target')} value={targetValue} mono/></div><div className="mt-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4"><Fact label={t('Severity')} value={selectedFinding.severity}/><Fact label={t('Confidence')} value={selectedFinding.confidence == null ? t('Not reported') : `${selectedFinding.confidence}%`}/><Fact label="Profile" value={profile}/><Fact label={t('Authorization')} value={authorized ? 'Confirmed' : 'Required'}/></div><div className="mt-4 grid gap-3 md:grid-cols-2"><Fact label={t('Authorized scope')} value={effectiveScope} mono/><Fact label="Target type" value={targetType.toUpperCase()}/></div></>}</>}
    </motion.section>
    <div className="flex items-center justify-between gap-3"><button type="button" onClick={()=>step===1?navigate(-1):setStep(s=>s-1)} className="inline-flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-medium"><ArrowLeft className="h-4 w-4"/>Back</button>{step<4?<button type="button" disabled={!canContinue} onClick={()=>setStep(s=>s+1)} className="inline-flex items-center gap-2 rounded-xl bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50">Continue<ArrowRight className="h-4 w-4"/></button>:<button type="button" disabled={!canContinue||submitting} onClick={submit} className="inline-flex items-center gap-2 rounded-xl bg-primary px-6 py-2.5 text-sm font-semibold text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50">{submitting?<><Loader2 className="h-4 w-4 animate-spin"/>Creating job…</>:<>Create Validation Job<ArrowRight className="h-4 w-4"/></>}</button>}</div>
  </div>
}

const severityTone = (severity: string) => ({critical:'border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400',high:'border-orange-500/30 bg-orange-500/10 text-orange-600 dark:text-orange-400',medium:'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400',low:'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400',informational:'border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-400'})[severity.toLowerCase()] || 'border-border bg-muted text-muted-foreground'
const Header = ({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) => <div><div className="text-xs font-semibold uppercase tracking-[0.16em] text-primary">{eyebrow}</div><h2 className="mt-2 text-2xl font-semibold tracking-tight">{title}</h2><p className="mt-1 max-w-3xl text-sm text-muted-foreground">{description}</p></div>
const Fact = ({ label, value, mono=false }: { label: string; value: string; mono?: boolean }) => <div className="rounded-2xl border bg-muted/20 p-4"><div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">{label}</div><div dir={mono?'ltr':undefined} className={cn('mt-2 truncate text-sm font-semibold',mono&&'font-mono text-[11px]')}>{value}</div></div>
