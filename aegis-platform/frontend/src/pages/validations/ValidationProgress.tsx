import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import { motion } from 'framer-motion'
import { Activity, ArrowRight, Ban, CheckCircle2, Clock, Loader2, Pause, Play, Radio, Shield, ShieldCheck, XCircle } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers, createWebSocket } from '@/services/api'

interface ProgressResponse {
  id: string
  finding_id: string | null
  status: string
  progress: number
  current_phase: string
  celery_task_id: string | null
  created_at: string
  completed_at: string | null
  error_message: string | null
}

const statusIcon = (status: string) => {
  if (status === 'completed') return <CheckCircle2 className="h-4 w-4 text-emerald-500" />
  if (status === 'running') return <Loader2 className="h-4 w-4 animate-spin text-primary" />
  if (status === 'queued') return <Clock className="h-4 w-4 text-amber-500" />
  return <XCircle className="h-4 w-4 text-destructive" />
}

export const ValidationProgress = () => {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [live, setLive] = useState<ProgressResponse | null>(null)
  const [wsConnected, setWsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  const query = useQuery({
    queryKey: ['validation-progress', id],
    queryFn: () => apiHelpers.get<ProgressResponse>(`/validations/${id}/progress`),
    enabled: Boolean(id),
    retry: false,
    refetchInterval: (state) => {
      const current = state.state.data as ProgressResponse | undefined
      if (!current || ['completed', 'failed', 'cancelled'].includes(current.status)) return false
      return wsConnected ? 5000 : 2000
    },
  })

  const display = live || query.data || null

  useEffect(() => {
    if (!id) return
    let closed = false
    const ws = createWebSocket(`/ws/validations/${id}`)
    wsRef.current = ws
    ws.onopen = () => setWsConnected(true)
    ws.onclose = () => {
      setWsConnected(false)
      if (!closed) setTimeout(() => query.refetch(), 1000)
    }
    ws.onerror = () => setWsConnected(false)
    ws.onmessage = event => {
      try {
        const message = JSON.parse(event.data)
        setLive(prev => ({ ...(prev || query.data || {}), ...(message.progress != null ? { progress: message.progress } : {}), ...(message.status ? { status: message.status } : {}), ...(message.current_phase ? { current_phase: message.current_phase } : {}) } as ProgressResponse))
        query.refetch()
      } catch {
        // Ignore malformed external WS frames; the authoritative state remains the API.
      }
    }
    return () => { closed = true; ws.close(); wsRef.current = null }
  }, [id, query.refetch])

  const handleCancel = async () => {
    if (!id) return
    try {
      await apiHelpers.post(`/validations/${id}/cancel`)
      toast.success('تم إرسال طلب الإلغاء')
      query.refetch()
    } catch (error: any) {
      const detail = error?.response?.data?.detail
      toast.error(typeof detail === 'string' ? detail : 'تعذر إلغاء التحقق عبر API')
    }
  }

  const handlePauseResume = async () => {
    if (!id || !display) return
    const action = display.status === 'paused' ? 'resume' : 'pause'
    try {
      await apiHelpers.post(`/validations/${id}/${action}`)
      query.refetch()
    } catch (error: any) {
      const detail = error?.response?.data?.detail
      toast.error(typeof detail === 'string' ? detail : `تعذر ${action === 'pause' ? 'إيقاف' : 'استئناف'} التحقق عبر API`)
    }
  }

  const phase = display?.current_phase || 'queued'
  const completed = display?.status === 'completed'
  const failed = display ? ['failed', 'cancelled'].includes(display.status) : false
  const phaseSteps = useMemo(() => {
    const known = ['queued', 'preflight', 'recon', 'nmap', 'nuclei', 'validation', 'completed']
    if (known.includes(phase)) return known
    return ['queued', phase, 'completed']
  }, [phase])

  if (query.isLoading && !display) return <div className="mx-auto w-full max-w-5xl space-y-4"><div className="h-32 animate-pulse rounded-3xl bg-muted" /><div className="h-72 animate-pulse rounded-3xl bg-muted" /></div>

  if (query.isError || !display) {
    return <div className="mx-auto flex min-h-[420px] max-w-3xl items-center justify-center"><div className="w-full rounded-3xl border bg-card p-8 text-center shadow-xl"><XCircle className="mx-auto h-10 w-10 text-destructive" /><h1 className="mt-4 text-xl font-semibold">Validation غير متاحة</h1><p className="mt-2 text-sm text-muted-foreground">تعذر تحميل الحالة الحقيقية من API. لم يتم إنشاء أو عرض أي بيانات محلية أو تجريبية.</p><Link to="/validations/new" className="mt-5 inline-flex items-center gap-2 rounded-xl bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground">Back to validation creation <ArrowRight className="h-4 w-4" /></Link></div></div>
  }

  return (
    <div className="mx-auto w-full max-w-6xl space-y-5 pb-10">
      <section className="relative overflow-hidden rounded-[2rem] border bg-card p-6 shadow-[0_30px_90px_rgba(0,0,0,.14)] md:p-8">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_80%_0%,color-mix(in_srgb,var(--primary)_11%,transparent),transparent_32%)]" />
        <div className="relative flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div><div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.18em] text-primary"><ShieldCheck className="h-4 w-4" /> Real Validation Execution</div><h1 className="mt-3 text-3xl font-semibold tracking-tight">Execution Timeline</h1><p className="mt-2 text-sm text-muted-foreground">الحالة التالية مأخوذة مباشرة من ValidationRun والـWebSocket المرتبط به.</p></div>
          <div className="flex items-center gap-2 text-xs"><span className={cn('inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 font-semibold', completed ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600' : failed ? 'border-red-500/30 bg-red-500/10 text-red-600' : 'border-primary/30 bg-primary/10 text-primary')}>{statusIcon(display.status)} {display.status.toUpperCase()}</span><span className={cn('inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5', wsConnected ? 'border-emerald-500/20 text-emerald-600' : 'border-border text-muted-foreground')}><Radio className="h-3 w-3" />{wsConnected ? 'WebSocket LIVE' : 'API polling'}</span></div>
        </div>
      </section>

      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Fact label="Validation ID" value={display.id} mono />
        <Fact label="Finding ID" value={display.finding_id || 'Unavailable'} mono />
        <Fact label="Current phase" value={display.current_phase} />
        <Fact label="Progress" value={`${display.progress}%`} />
      </section>

      <section className="rounded-3xl border bg-card p-5 shadow-sm md:p-7">
        <div className="flex items-center justify-between"><div><p className="text-xs font-semibold uppercase tracking-[0.16em] text-primary">Execution state</p><h2 className="mt-1 text-xl font-semibold">Server-authoritative progress</h2></div><Activity className="h-5 w-5 text-primary" /></div>
        <div className="mt-6 h-3 overflow-hidden rounded-full bg-muted"><motion.div initial={{ width: 0 }} animate={{ width: `${Math.max(0, Math.min(100, display.progress))}%` }} className={cn('h-full rounded-full', completed ? 'bg-emerald-500' : failed ? 'bg-destructive' : 'bg-primary')} transition={{ duration: .5 }} /></div>
        <div className="mt-2 flex justify-between text-xs text-muted-foreground"><span>{display.current_phase}</span><span>{display.progress}%</span></div>
        <div className="mt-7 grid gap-2 md:grid-cols-7">{phaseSteps.map((step, index) => { const active = step === phase; const done = completed || index < phaseSteps.indexOf(phase); return <div key={`${step}-${index}`} className={cn('rounded-xl border px-3 py-3 text-center text-xs', active ? 'border-primary bg-primary/5 text-primary' : done ? 'border-emerald-500/20 bg-emerald-500/5 text-emerald-700 dark:text-emerald-400' : 'border-border text-muted-foreground')}><div className="mx-auto mb-2 grid h-7 w-7 place-items-center rounded-full border">{done ? <CheckCircle2 className="h-4 w-4" /> : active ? <Loader2 className="h-4 w-4 animate-spin" /> : <span>{index + 1}</span>}</div><span className="capitalize">{step}</span></div> })}</div>
      </section>

      <section className="rounded-3xl border bg-card p-5 shadow-sm md:p-7">
        <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="font-semibold">Execution controls</h2><p className="mt-1 text-xs text-muted-foreground">كل الأوامر أدناه تعتمد على endpoints حقيقية. لا يوجد local fallback.</p></div><div className="flex flex-wrap gap-2">{!completed && !failed && <><button onClick={handlePauseResume} className="inline-flex items-center gap-2 rounded-xl border px-4 py-2 text-xs font-semibold hover:bg-muted">{display.status === 'paused' ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}{display.status === 'paused' ? 'Resume' : 'Pause'}</button><button onClick={handleCancel} className="inline-flex items-center gap-2 rounded-xl border border-red-500/20 px-4 py-2 text-xs font-semibold text-red-600 hover:bg-red-500/5"><Ban className="h-3.5 w-3.5" />Cancel</button></>}{completed && <button onClick={() => navigate(`/validations/${id}/results`)} className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground">View Results <ArrowRight className="h-3.5 w-3.5" /></button>}</div></div>
        {display.error_message && <div className="mt-5 rounded-2xl border border-red-500/20 bg-red-500/5 p-4 text-xs text-red-600 dark:text-red-400">{display.error_message}</div>}
      </section>
    </div>
  )
}

const Fact = ({ label, value, mono }: { label: string; value: string; mono?: boolean }) => <div className="rounded-2xl border bg-muted/20 p-4"><div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">{label}</div><div dir={mono ? 'ltr' : undefined} className={cn('mt-2 truncate font-semibold', mono ? 'font-mono text-[11px]' : 'text-sm')}>{value}</div></div>
