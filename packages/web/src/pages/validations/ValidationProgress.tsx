import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import { motion } from 'framer-motion'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Ban,
  CheckCircle2,
  Clock,
  Layers,
  Loader2,
  Pause,
  Play,
  Radio,
  RefreshCw,
  Shield,
  ShieldCheck,
  XCircle,
  Zap,
} from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers, createWebSocket } from '@/services/api'

interface EngineState {
  id: string
  phase: string
  status: string
  progress: number
  findings: number
}

interface GroupState {
  id: string
  label: string
  desc: string
  status: string
  engines: Array<{
    id: string
    label: string
    status: string
    progress: number
    findings: number
  }>
}

interface ProgressResponse {
  id: string
  target_type: string
  target_value: string
  scope: string
  profile: string
  engines_requested: string[]
  status: string
  progress: number
  current_phase: string
  created_at: string
  completed_at: string | null
  groups: GroupState[]
  engines: EngineState[]
  phases: string[]
  live_events: Array<{ ts: string; type: string; message: string; meta?: Record<string, unknown> }>
  error?: string | null
}

const statusIcon = (status: string) => {
  if (status === 'completed' || status === 'unsupported') return <CheckCircle2 className="h-4 w-4 text-emerald-500" />
  if (status === 'running') return <Loader2 className="h-4 w-4 animate-spin text-primary" />
  if (status === 'queued' || status === 'pending') return <Clock className="h-4 w-4 text-amber-500" />
  if (status === 'failed' || status === 'cancelled') return <XCircle className="h-4 w-4 text-destructive" />
  if (status === 'paused') return <Pause className="h-4 w-4 text-amber-500" />
  return <span className="grid h-4 w-4 place-items-center rounded-full border border-muted-foreground/40"><span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/50" /></span>
}

export const ValidationProgress = () => {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [live, setLive] = useState<ProgressResponse | null>(null)
  const [wsConnected, setWsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  const query = useQuery({
    queryKey: ['validation-progress', id],
    enabled: Boolean(id),
    queryFn: () => apiHelpers.get<ProgressResponse>(`/validations/${id}/progress`),
    refetchInterval: (q) => {
      const value = q.state.data as ProgressResponse | undefined
      if (!value || ['completed', 'failed', 'cancelled'].includes(value.status)) return false
      return wsConnected ? 5000 : 2000
    },
    retry: 2,
  })

  const display = live ?? query.data ?? null

  useEffect(() => {
    if (!id) return
    let disposed = false
    let ws: WebSocket | null = null

    const connect = () => {
      if (disposed) return
      try {
        ws = createWebSocket(`/ws/validations/${id}`)
        wsRef.current = ws
        ws.onopen = () => setWsConnected(true)
        ws.onclose = () => {
          setWsConnected(false)
          if (!disposed) window.setTimeout(connect, 3000)
        }
        ws.onerror = () => setWsConnected(false)
        ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data) as { type?: string; overall?: number }
            if (message.overall !== undefined) {
              setLive((previous) => previous ? { ...previous, progress: message.overall } : previous)
            }
            query.refetch()
            if (message.type === 'finding.created') toast.info('Finding correlated')
            if (message.type === 'validation.completed') toast.success('Validation completed — results are ready')
            if (message.type === 'validation.failed') toast.error('Validation failed')
          } catch {
            // Ignore malformed live events; polling remains authoritative.
          }
        }
      } catch {
        setWsConnected(false)
      }
    }

    connect()
    return () => {
      disposed = true
      ws?.close()
      wsRef.current = null
    }
  }, [id, query.refetch])

  const activeEngine = useMemo(() => {
    if (!display) return null
    return display.engines.find((engine) => engine.status === 'running')
      ?? display.engines.find((engine) => engine.status === 'queued')
      ?? null
  }, [display])

  const action = async (name: 'pause' | 'resume' | 'cancel') => {
    if (!id) return
    try {
      await apiHelpers.post(`/validations/${id}/${name}`)
      await query.refetch()
      toast.success(name === 'cancel' ? 'تم إلغاء التحقق' : name === 'pause' ? 'تم إيقاف التحقق مؤقتاً' : 'تم استئناف التحقق')
    } catch (error: any) {
      toast.error(error?.response?.data?.detail || error?.message || 'فشل تنفيذ العملية')
    }
  }

  if (query.isLoading && !display) {
    return <div className="mx-auto max-w-6xl p-6"><div className="space-y-4 animate-pulse"><div className="h-12 rounded-xl bg-muted" /><div className="h-64 rounded-xl bg-muted" /><div className="h-56 rounded-xl bg-muted" /></div></div>
  }

  if (query.isError && !display) {
    return (
      <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center">
        <div>
          <AlertTriangle className="mx-auto h-9 w-9 text-destructive" />
          <h1 className="mt-4 text-lg font-bold">تعذر تحميل التحقق</h1>
          <p className="mt-2 text-sm text-muted-foreground">لم يُعثر على Validation بهذا المعرّف في محرك التنفيذ الحي، أو أن خدمة التشغيل غير متاحة.</p>
          <div className="mt-5 flex justify-center gap-2">
            <button type="button" onClick={() => query.refetch()} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> إعادة المحاولة</button>
            <Link to="/validations/new" className="inline-flex items-center gap-2 rounded-lg bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground">إنشاء تحقق جديد</Link>
          </div>
        </div>
      </div>
    )
  }

  if (!display) return null

  const isDone = display.status === 'completed'
  const isFailed = display.status === 'failed' || display.status === 'cancelled'
  const progress = Math.max(0, Math.min(100, display.progress))

  return (
    <div className="mx-auto max-w-6xl space-y-4 p-6">
      <section className="overflow-hidden rounded-xl border bg-card">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b bg-muted/20 px-5 py-4">
          <div className="flex flex-wrap items-center gap-3">
            <ShieldCheck className="h-5 w-5 text-primary" />
            <span className="font-mono text-sm font-semibold">Validation #{display.id}</span>
            <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium', isDone ? 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/30' : isFailed ? 'border-destructive/20 bg-destructive/10 text-destructive' : 'border-primary/20 bg-primary/10 text-primary')}>
              <Radio className={cn('h-3 w-3', !isDone && !isFailed && 'animate-pulse')} /> {display.status.toUpperCase()}
            </span>
            <span className="flex items-center gap-1 text-xs text-muted-foreground"><Clock className="h-3 w-3" />{new Date(display.created_at).toLocaleString()}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm font-bold">{progress}%</span>
            {!isDone && !isFailed && display.status !== 'paused' && <button type="button" onClick={() => action('pause')} className="inline-flex items-center gap-1 rounded-lg border px-3 py-1.5 text-xs hover:bg-muted"><Pause className="h-3 w-3" /> إيقاف</button>}
            {display.status === 'paused' && <button type="button" onClick={() => action('resume')} className="inline-flex items-center gap-1 rounded-lg border px-3 py-1.5 text-xs hover:bg-muted"><Play className="h-3 w-3" /> استئناف</button>}
            {!isDone && !isFailed && <button type="button" onClick={() => action('cancel')} className="inline-flex items-center gap-1 rounded-lg border px-3 py-1.5 text-xs text-destructive hover:bg-destructive/5"><Ban className="h-3 w-3" /> إلغاء</button>}
            {isDone && <button type="button" onClick={() => navigate(`/validations/${id}/results`)} className="inline-flex items-center gap-1 rounded-lg bg-primary px-4 py-1.5 text-xs font-medium text-primary-foreground">النتائج <ArrowRight className="h-3 w-3" /></button>}
          </div>
        </div>
        <div className="space-y-3 px-5 py-4">
          <div className="flex flex-wrap gap-4 text-xs">
            <span className="inline-flex items-center gap-1"><Layers className="h-3 w-3 text-muted-foreground" />Target <span className="font-mono font-medium" dir="ltr">{display.target_value}</span></span>
            <span className="inline-flex items-center gap-1"><Shield className="h-3 w-3 text-muted-foreground" />Scope <span className="font-mono" dir="ltr">{display.scope}</span></span>
            <span className={cn('inline-flex items-center gap-1', wsConnected ? 'text-emerald-600' : 'text-amber-600')}><Activity className="h-3 w-3" />{wsConnected ? 'WebSocket LIVE' : 'Polling'}</span>
            <span className="font-mono text-muted-foreground">{display.profile}</span>
          </div>
          <div>
            <div className="mb-1 flex justify-between text-xs"><span className="text-muted-foreground">Overall Progress</span><span className="font-medium">{progress}% — {display.current_phase}</span></div>
            <div className="h-2.5 overflow-hidden rounded-full bg-muted"><motion.div initial={{ width: 0 }} animate={{ width: `${progress}%` }} className={cn('h-full rounded-full', isDone ? 'bg-emerald-500' : isFailed ? 'bg-destructive' : 'bg-primary')} /></div>
          </div>
          {display.error && <div className="rounded-lg border border-destructive/20 bg-destructive/5 px-3 py-2 text-xs text-destructive">{display.error}</div>}
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-3">
        <section className="rounded-xl border bg-card p-4">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold"><Layers className="h-4 w-4 text-primary" /> مراحل التنفيذ</h2>
          <div className="space-y-1.5">
            {display.groups.map((group) => (
              <div key={group.id} className={cn('rounded-lg border px-3 py-2', group.status === 'running' && 'border-primary/30 bg-primary/5')}>
                <div className="flex items-center justify-between gap-2"><div className="flex items-center gap-2">{statusIcon(group.status)}<span className="text-xs font-medium">{group.label}</span></div><span className="text-[11px] capitalize text-muted-foreground">{group.status}</span></div>
                <p className="mt-1 pl-6 text-[11px] text-muted-foreground">{group.desc}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-xl border bg-card p-4 lg:col-span-2">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold"><Zap className="h-4 w-4 text-amber-500" /> المحرك النشط</h2>
          {activeEngine ? <div className="rounded-lg border bg-muted/20 p-4"><div className="flex items-center justify-between"><span className="font-mono text-sm font-semibold">{activeEngine.id}</span><span className="rounded-full border bg-primary/10 px-2 py-0.5 text-xs text-primary">{activeEngine.status} · {activeEngine.progress}%</span></div><div className="mt-3 h-1.5 overflow-hidden rounded-full bg-muted"><div className="h-full bg-primary transition-all" style={{ width: `${activeEngine.progress}%` }} /></div><div className="mt-3 grid grid-cols-3 gap-3 text-xs"><div><div className="text-muted-foreground">Phase</div><div className="font-mono">{activeEngine.phase}</div></div><div><div className="text-muted-foreground">Findings</div><div className="font-semibold">{activeEngine.findings}</div></div><div><div className="text-muted-foreground">Status</div><div>{activeEngine.status}</div></div></div></div> : <div className="rounded-lg border border-dashed p-7 text-center text-sm text-muted-foreground">{isDone ? 'اكتمل التنفيذ الحقيقي' : isFailed ? 'توقف التنفيذ' : 'بانتظار المحرك التالي…'}</div>}
          <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3">
            {display.engines.filter((engine) => display.engines_requested.includes(engine.id)).map((engine) => <div key={engine.id} className={cn('rounded-lg border px-2.5 py-2', engine.status === 'running' && 'border-primary/30 bg-primary/5', engine.status === 'completed' && 'bg-emerald-50/40 dark:bg-emerald-950/20')}><div className="flex items-center justify-between gap-2"><span className="truncate font-mono text-[11px]">{engine.id}</span>{statusIcon(engine.status)}</div><div className="mt-1 text-[10px] text-muted-foreground">{engine.progress}% · {engine.findings} findings</div></div>)}
          </div>
        </section>
      </div>

      <section className="rounded-xl border bg-card">
        <div className="flex items-center justify-between border-b px-5 py-3"><h2 className="flex items-center gap-2 text-sm font-semibold"><Activity className="h-4 w-4 text-primary" /> Live execution events</h2><span className="text-[11px] text-muted-foreground">{display.live_events.length} events</span></div>
        <div className="max-h-[360px] overflow-auto divide-y">
          {display.live_events.length ? display.live_events.slice().reverse().map((event, index) => <div key={`${event.ts}-${event.type}-${index}`} className="grid grid-cols-[130px_1fr] gap-3 px-5 py-2.5 text-xs"><span className="font-mono text-muted-foreground">{new Date(event.ts).toLocaleTimeString()}</span><div><div className="font-medium">{event.type}</div><div className="mt-0.5 text-muted-foreground">{event.message}</div></div></div>) : <div className="p-8 text-center text-sm text-muted-foreground">لا توجد أحداث تنفيذ حتى الآن.</div>}
        </div>
      </section>

      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <Link to="/dashboard" className="hover:text-primary">العودة إلى لوحة التحكم</Link>
        <span className="inline-flex items-center gap-1"><CheckCircle2 className="h-3.5 w-3.5 text-primary" />المصدر الوحيد للحالة: Validation Runtime</span>
      </div>
    </div>
  )
}
