import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { toast } from 'sonner'
import { AlertTriangle, ArrowRight, CheckCircle2, ChevronDown, Loader2, Search, ShieldCheck, Target } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'

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

const severityTone: Record<string, string> = {
  critical: 'border-red-500/30 bg-red-500/8 text-red-600 dark:text-red-400',
  high: 'border-orange-500/30 bg-orange-500/8 text-orange-600 dark:text-orange-400',
  medium: 'border-amber-500/30 bg-amber-500/8 text-amber-700 dark:text-amber-400',
  low: 'border-emerald-500/30 bg-emerald-500/8 text-emerald-700 dark:text-emerald-400',
  informational: 'border-slate-500/30 bg-slate-500/8 text-slate-600 dark:text-slate-400',
}

export const NewValidation = () => {
  const navigate = useNavigate()
  const [selectedFindingId, setSelectedFindingId] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [scope, setScope] = useState('')
  const [query, setQuery] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const findingsQuery = useQuery({
    queryKey: ['validation-source-findings'],
    queryFn: () => apiHelpers.get<Finding[]>('/vulnerabilities?limit=200'),
    staleTime: 10_000,
  })

  const findings = useMemo(() => {
    const items = Array.isArray(findingsQuery.data) ? findingsQuery.data : []
    const normalized = query.trim().toLowerCase()
    return items
      .filter((finding) => ['nmap', 'nuclei'].includes(String(finding.source_engine || '').toLowerCase()))
      .filter((finding) => !['fixed', 'false_positive', 'accepted_risk', 'wont_fix', 'duplicate'].includes(finding.status))
      .filter((finding) => {
        if (!normalized) return true
        return [finding.title, finding.asset_name, finding.asset_target, finding.source_engine, finding.severity].some(value => String(value || '').toLowerCase().includes(normalized))
      })
  }, [findingsQuery.data, query])

  const selectedFinding = useMemo(
    () => (Array.isArray(findingsQuery.data) ? findingsQuery.data : []).find(item => item.id === selectedFindingId) || null,
    [findingsQuery.data, selectedFindingId],
  )

  const targetType = selectedFinding?.source_engine === 'nmap' ? 'ip' : selectedFinding?.source_engine === 'nuclei' ? 'url' : ''
  const targetValue = selectedFinding?.asset_target || ''
  const effectiveScope = scope.trim() || targetValue

  const createValidation = async () => {
    if (!selectedFinding) return toast.error('اختر Finding حقيقية قبل إنشاء مهمة التحقق')
    if (!selectedFinding.source_engine || !['nmap', 'nuclei'].includes(selectedFinding.source_engine.toLowerCase())) {
      return toast.error('هذه Finding لا تملك محرك تحقق مدعومًا')
    }
    if (!targetValue) return toast.error('الـFinding المختارة لا تحتوي على هدف مرتبط بالأصل')
    if (!authorized) return toast.error('يجب تأكيد التفويض قبل التنفيذ')
    if (!effectiveScope) return toast.error('نطاق التنفيذ مطلوب')

    setSubmitting(true)
    try {
      const response = await apiHelpers.post<{ id: string; finding_id: string }>('/validations', {
        finding_id: selectedFinding.id,
        target_type: targetType,
        target_value: targetValue,
        profile: 'custom',
        engines: [selectedFinding.source_engine.toLowerCase()],
        scope: effectiveScope,
        authorized: true,
        duration_minutes: 60,
        rate_limit: 5,
        extra: { source: 'finding-investigation' },
      })

      if (!response?.id || response.finding_id !== selectedFinding.id) {
        throw new Error('Validation service did not return a finding-linked job')
      }

      toast.success('تم إنشاء مهمة تحقق حقيقية مرتبطة بالـFinding')
      navigate(`/validations/${response.id}/progress`, { replace: true })
    } catch (error: any) {
      const detail = error?.response?.data?.detail
      toast.error(typeof detail === 'string' ? detail : error?.message || 'تعذر إنشاء مهمة التحقق')
    } finally {
      setSubmitting(false)
    }
  }

  if (findingsQuery.isLoading) {
    return <div className="mx-auto w-full max-w-6xl space-y-6"><div className="h-32 animate-pulse rounded-3xl bg-muted" /><div className="h-80 animate-pulse rounded-3xl bg-muted" /></div>
  }

  if (findingsQuery.isError) {
    return <div className="mx-auto flex min-h-[420px] w-full max-w-4xl items-center justify-center"><div className="w-full rounded-3xl border border-red-500/20 bg-card p-8 text-center shadow-xl"><AlertTriangle className="mx-auto h-10 w-10 text-red-500" /><h1 className="mt-4 text-xl font-semibold">تعذر تحميل Findings</h1><p className="mt-2 text-sm text-muted-foreground">لا يمكن إنشاء Real Validation بدون بيانات Finding حقيقية من الـAPI.</p><button onClick={() => findingsQuery.refetch()} className="mt-5 rounded-xl bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground">إعادة المحاولة</button></div></div>
  }

  return (
    <div className="mx-auto w-full max-w-6xl space-y-6 pb-10">
      <section className="relative overflow-hidden rounded-[2rem] border bg-card p-6 shadow-[0_30px_90px_rgba(0,0,0,.14)] md:p-8">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_75%_0%,color-mix(in_srgb,var(--primary)_12%,transparent),transparent_32%)]" />
        <div className="relative">
          <div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/5 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.18em] text-primary"><ShieldCheck className="h-3.5 w-3.5" /> Real Validation</div>
          <h1 className="mt-4 text-3xl font-semibold tracking-tight md:text-4xl">إنشاء تحقق مرتبط بدليل حقيقي</h1>
          <p className="mt-2 max-w-3xl text-sm leading-7 text-muted-foreground">لا يسمح AegisScan بإنشاء Validation معزولة. يجب اختيار Finding موجودة من قاعدة البيانات، ثم يُشتق منها المحرك والهدف ويُرسل التنفيذ مع عقدة authorization قابلة للتدقيق.</p>
        </div>
      </section>

      <section className="rounded-3xl border bg-card p-5 shadow-sm md:p-7">
        <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <div><p className="text-xs font-semibold uppercase tracking-[0.16em] text-primary">01 / Finding source</p><h2 className="mt-1 text-xl font-semibold">اختر Finding حقيقية</h2><p className="mt-1 text-sm text-muted-foreground">المعروض هنا مصدره `/vulnerabilities` فقط. لا توجد نتائج تجريبية.</p></div>
          <div className="relative w-full md:w-80"><Search className="absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><input value={query} onChange={e => setQuery(e.target.value)} placeholder="بحث بالاسم أو الأصل أو المحرك" className="h-10 w-full rounded-xl border bg-background ps-9 pe-3 text-sm outline-none focus:ring-2 focus:ring-primary/20" /></div>
        </div>

        <div className="mt-5 max-h-[430px] space-y-2 overflow-y-auto pe-1">
          {findings.map(finding => (
            <button key={finding.id} type="button" onClick={() => { setSelectedFindingId(finding.id); setScope(finding.asset_target || '') }} className={cn('w-full rounded-2xl border p-4 text-start transition-all', selectedFindingId === finding.id ? 'border-primary bg-primary/5 shadow-[0_12px_35px_color-mix(in_srgb,var(--primary)_12%,transparent)]' : 'border-border/70 hover:-translate-y-0.5 hover:bg-muted/30')}>
              <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className={cn('rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase', severityTone[finding.severity] || 'border-border bg-muted text-muted-foreground')}>{finding.severity}</span><span className="rounded-full border px-2 py-0.5 text-[10px] font-medium text-muted-foreground">{finding.source_engine}</span><span className="font-mono text-[10px] text-muted-foreground">{finding.id}</span></div><div className="mt-2 truncate text-sm font-semibold">{finding.title}</div><div className="mt-1 truncate text-xs text-muted-foreground">{finding.asset_name || finding.asset_target || 'Asset unavailable'}</div></div>
                <div className="flex items-center gap-2 text-xs text-muted-foreground"><span>Risk {finding.risk_score}</span>{selectedFindingId === finding.id && <CheckCircle2 className="h-5 w-5 text-primary" />}</div>
              </div>
            </button>
          ))}
          {!findings.length && <div className="rounded-2xl border border-dashed p-10 text-center text-sm text-muted-foreground">لا توجد Findings قابلة للتحقق الفعلي ضمن البيانات الحالية.</div>}
        </div>
      </section>

      <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-3xl border bg-card p-5 shadow-sm md:p-7">
        <div className="flex items-center gap-2"><p className="text-xs font-semibold uppercase tracking-[0.16em] text-primary">02 / Execution contract</p></div>
        {!selectedFinding ? (
          <div className="mt-5 rounded-2xl border border-dashed p-10 text-center"><Target className="mx-auto h-8 w-8 text-muted-foreground" /><h3 className="mt-3 font-semibold">اختر Finding أولًا</h3><p className="mt-1 text-sm text-muted-foreground">لن يظهر زر التنفيذ قبل وجود Finding حقيقية مرتبطة بهدف ومحرك.</p></div>
        ) : (
          <>
            <div className="mt-5 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
              <Fact label="Finding" value={selectedFinding.id} mono />
              <Fact label="Engine" value={selectedFinding.source_engine} />
              <Fact label="Target" value={targetValue} mono />
              <Fact label="Target type" value={targetType.toUpperCase()} />
            </div>
            <div className="mt-5 rounded-2xl border bg-muted/20 p-4"><div className="text-xs font-semibold uppercase tracking-[0.15em] text-muted-foreground">Authorized scope</div><input value={scope} onChange={e => setScope(e.target.value)} dir="ltr" className="mt-3 h-11 w-full rounded-xl border bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-primary/20" placeholder={targetValue} /><p className="mt-2 text-[11px] text-muted-foreground">يُرسل النطاق إلى backend ليخضع للـserver-side authorization. لا يوجد bypass من الواجهة.</p></div>
            <label className={cn('mt-5 flex cursor-pointer gap-3 rounded-2xl border p-4 transition', authorized ? 'border-emerald-500/30 bg-emerald-500/5' : 'hover:bg-muted/30')}><input type="checkbox" checked={authorized} onChange={e => setAuthorized(e.target.checked)} className="mt-1" /><span><span className="block text-sm font-semibold">أؤكد أن هذا الهدف مصرح به</span><span className="mt-1 block text-xs leading-5 text-muted-foreground">سيتم تسجيل التفويض ضمن ValidationRun، ولن يتم تجاوز فحص النطاق على الخادم.</span></span></label>

            <div className="mt-6 flex flex-col-reverse gap-3 sm:flex-row sm:items-center sm:justify-between">
              <button type="button" onClick={() => navigate(-1)} className="rounded-xl border px-4 py-2.5 text-sm font-medium hover:bg-muted">إلغاء</button>
              <button type="button" disabled={submitting || !authorized || !targetValue} onClick={createValidation} className="inline-flex items-center justify-center gap-2 rounded-xl bg-primary px-6 py-3 text-sm font-semibold text-primary-foreground shadow-[0_12px_30px_color-mix(in_srgb,var(--primary)_25%,transparent)] transition hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-50">{submitting ? <><Loader2 className="h-4 w-4 animate-spin" /> جارٍ إنشاء المهمة…</> : <>Create Validation Job <ArrowRight className="h-4 w-4" /></>}</button>
            </div>
          </>
        )}
      </motion.section>
    </div>
  )
}

const Fact = ({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) => <div className="rounded-2xl border bg-muted/20 p-4"><div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">{label}</div><div dir={mono ? 'ltr' : undefined} className={cn('mt-2 truncate text-sm font-semibold', mono && 'font-mono text-[12px]')}>{value}</div></div>
