import { useEffect, useState, useRef, useMemo } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import { motion } from 'framer-motion'
import { ShieldCheck, Clock, Zap, CheckCircle2, Loader2, AlertTriangle, XCircle, Pause, Play, Ban, ArrowRight, Radio, Activity, Search, FileText, Shield, Layers } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers, createWebSocket } from '@/services/api'

type ProgressResponse = {
  id: string
  target_type: string
  target_value: string
  scope: string
  status: string
  progress: number
  current_phase: string
  created_at: string
  completed_at: string | null
  groups: { id: string; label: string; desc: string; status: string; engines: { id: string; label: string; status: string; progress: number; findings: number }[] }[]
  engines: { id: string; phase: string; status: string; progress: number; findings: number }[]
  phases: string[]
  live_events: { ts: string; type: string; message: string; meta?: any }[]
}

const statusIcon = (s: string) => {
  if (s === 'completed') return <CheckCircle2 className="h-4 w-4 text-emerald-500" />
  if (s === 'running') return <Loader2 className="h-4 w-4 text-primary animate-spin" />
  if (s === 'queued') return <Clock className="h-4 w-4 text-amber-500" />
  if (s === 'failed' || s === 'cancelled') return <XCircle className="h-4 w-4 text-destructive" />
  if (s === 'paused') return <Pause className="h-4 w-4 text-amber-500" />
  if (s === 'skipped') return <span className="h-4 w-4 grid place-items-center text-[10px] text-muted-foreground">—</span>
  return <span className="h-4 w-4 rounded-full border border-muted-foreground/40 grid place-items-center"><span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/50" /></span>
}

export const ValidationProgress = () => {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [live, setLive] = useState<ProgressResponse | null>(null)
  const [wsConnected, setWsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  const { data, refetch, isLoading } = useQuery({
    queryKey: ['validation-progress', id],
    queryFn: async () => {
      // try real API, fallback to localStorage mock
      try {
        return await apiHelpers.get<ProgressResponse>(`/validations/${id}/progress`)
      } catch {
        const raw = localStorage.getItem(`validation:${id}`)
        if (raw) {
          const v = JSON.parse(raw)
          // synthesize minimal ProgressResponse for mock
          return {
            id: v.id,
            target_type: v.target_type,
            target_value: v.target_value,
            scope: v.scope,
            status: 'queued',
            progress: 0,
            current_phase: 'queued',
            created_at: v.created_at,
            completed_at: null,
            groups: [],
            engines: [],
            phases: ["queued","initializing","recon","discovery","enumeration","analysis","validation","reporting","completed"],
            live_events: [{ ts: v.created_at, type: 'validation.queued', message: `Validation ${v.id} queued (mock)` }]
          } as ProgressResponse
        }
        throw new Error('Validation not found')
      }
    },
    refetchInterval: (query) => {
      const d = query.state.data as ProgressResponse | undefined
      if (!d) return 2000
      if (d.status === 'completed' || d.status === 'failed' || d.status === 'cancelled') return false
      // if WS connected, poll less frequently
      return wsConnected ? 5000 : 2000
    },
    enabled: !!id,
  })

  const display: ProgressResponse | null = live || (data as ProgressResponse) || null

  // WebSocket: unified contract validation.started | phase.started | engine.started | engine.progress | finding.created | engine.completed | phase.completed | validation.completed | validation.failed
  useEffect(() => {
    if (!id) return
    let ws: WebSocket | null = null
    let closed = false
    const connect = () => {
      try {
        ws = createWebSocket(`/ws/validations/${id}`)
        wsRef.current = ws
        ws.onopen = () => setWsConnected(true)
        ws.onclose = () => {
          setWsConnected(false)
          if (!closed && display?.status !== 'completed') {
            setTimeout(() => { if (!closed) connect() }, 3000)
          }
        }
        ws.onerror = () => setWsConnected(false)
        ws.onmessage = (ev) => {
          try {
            const msg = JSON.parse(ev.data)
            // any event triggers refetch to get full state; for engine.progress we can patch optimistically
            if (msg.type === 'engine.progress' || msg.type === 'validation.completed' || msg.type === 'engine.completed') {
              // optimistic update
              setLive(prev => {
                const base = (prev || data) as ProgressResponse | null
                if (!base) return prev
                // just refetch for correctness, but also update progress quickly
                return { ...base, progress: msg.overall ?? base.progress }
              })
            }
            // always refetch to sync groups/engines/live_events
            refetch()
            // toast for key events
            if (msg.type === 'finding.created') toast.info(msg.message || 'Finding correlated')
            if (msg.type === 'validation.completed') toast.success('Validation completed — ready for Results')
            if (msg.type === 'validation.failed') toast.error(msg.reason || 'Validation failed')
          } catch {}
        }
      } catch {
        setWsConnected(false)
      }
    }
    connect()
    return () => { closed = true; ws?.close(); wsRef.current = null }
  }, [id, refetch, data, display?.status])

  const activeEngine = useMemo(() => {
    if (!display) return null
    return display.engines.find(e => e.status === 'running') || display.engines.find(e => e.status === 'queued') || null
  }, [display])

  const handleCancel = async () => {
    try {
      await apiHelpers.post(`/validations/${id}/cancel`)
      toast.success('تم إلغاء التحقق')
      refetch()
    } catch {
      // mock fallback
      toast.success('تم إلغاء التحقق (mock)')
    }
  }
  const handlePauseResume = async () => {
    if (!display) return
    const isPaused = display.status === 'paused'
    try {
      await apiHelpers.post(`/validations/${id}/${isPaused ? 'resume' : 'pause'}`)
      refetch()
    } catch {}
  }

  if (isLoading && !display) {
    return <div className="p-6 max-w-5xl mx-auto"><div className="animate-pulse space-y-4"><div className="h-10 bg-muted rounded w-1/3" /><div className="h-64 bg-muted rounded" /></div></div>
  }
  if (!display) {
    return <div className="p-6 max-w-5xl mx-auto"><p className="text-muted-foreground">Validation not found</p><Link to="/validations/new" className="text-primary underline text-sm">إنشاء تحقق جديد</Link></div>
  }

  const isDone = display.status === 'completed'
  const isFailed = display.status === 'failed' || display.status === 'cancelled'

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-4">
      {/* Header Command Center */}
      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="px-5 py-4 flex flex-wrap items-center justify-between gap-3 border-b bg-muted/20">
          <div className="flex items-center gap-3">
            <ShieldCheck className="h-5 w-5 text-primary" />
            <span className="font-mono text-sm font-semibold">Validation #{display.id}</span>
            <span className={cn('inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border',
              isDone ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40' :
              isFailed ? 'bg-destructive/10 text-destructive border-destructive/20' :
              'bg-primary/10 text-primary border-primary/20')}>
              <Radio className={cn('h-3 w-3', !isDone && !isFailed && 'animate-pulse')} />
              {isDone ? 'COMPLETED' : isFailed ? display.status.toUpperCase() : 'LIVE'}
            </span>
            <span className="text-xs text-muted-foreground flex items-center gap-1"><Clock className="h-3 w-3" />{new Date(display.created_at).toLocaleString()}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm font-bold">{display.progress}%</span>
            {!isDone && !isFailed && (
              <>
                <button onClick={handlePauseResume} className="px-3 py-1.5 rounded-lg border bg-card text-xs hover:bg-muted inline-flex items-center gap-1">
                  {display.status === 'paused' ? <><Play className="h-3 w-3" /> Resume</> : <><Pause className="h-3 w-3" /> Pause</>}
                </button>
                <button onClick={handleCancel} className="px-3 py-1.5 rounded-lg border bg-card text-xs hover:bg-muted inline-flex items-center gap-1">
                  <Ban className="h-3 w-3" /> Cancel
                </button>
              </>
            )}
            {isDone && (
              <button onClick={() => navigate(`/validations/${id}/results`)} className="px-4 py-1.5 rounded-lg bg-primary text-primary-foreground text-xs font-medium inline-flex items-center gap-1">
                View Results <ArrowRight className="h-3 w-3" />
              </button>
            )}
          </div>
        </div>

        <div className="px-5 py-4 space-y-3">
          <div className="flex flex-wrap gap-4 text-xs">
            <span className="inline-flex items-center gap-1"><Layers className="h-3 w-3 text-muted-foreground" />Target <span className="font-mono font-medium" dir="ltr">{display.target_value}</span></span>
            <span className="inline-flex items-center gap-1"><Shield className="h-3 w-3 text-muted-foreground" />Scope <span className="font-mono" dir="ltr">{display.scope}</span></span>
            <span className={cn('inline-flex items-center gap-1', wsConnected ? 'text-emerald-600' : 'text-amber-600')}><Activity className="h-3 w-3" />{wsConnected ? 'WebSocket LIVE' : 'Polling'}</span>
          </div>

          <div>
            <div className="flex justify-between text-xs mb-1"><span className="text-muted-foreground">Overall Progress</span><span className="font-medium">{display.progress}% — {display.current_phase}</span></div>
            <div className="h-2.5 rounded-full bg-muted overflow-hidden">
              <motion.div initial={{ width: 0 }} animate={{ width: `${display.progress}%` }} transition={{ duration: 0.6 }} className={cn('h-full rounded-full', isDone ? 'bg-emerald-500' : isFailed ? 'bg-destructive' : 'bg-primary')} />
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* PHASES */}
        <div className="rounded-xl border bg-card p-4 lg:col-span-1">
          <h3 className="text-sm font-semibold flex items-center gap-2 mb-3"><Layers className="h-4 w-4 text-primary" /> PHASES</h3>
          <div className="space-y-1.5">
            {(display.groups.length ? display.groups : [{ id: display.current_phase, label: display.current_phase, desc: '', status: display.status, engines: [] }]).map(g => (
              <div key={g.id} className={cn('rounded-lg border px-3 py-2 flex items-center justify-between', g.status === 'running' ? 'bg-primary/5 border-primary/30' : g.status === 'completed' ? 'bg-emerald-50/50 dark:bg-emerald-950/20 border-emerald-200/50' : 'bg-card')}>
                <div className="flex items-center gap-2">
                  {statusIcon(g.status)}
                  <div>
                    <div className="text-xs font-medium capitalize">{g.label}</div>
                    <div className="text-[11px] text-muted-foreground line-clamp-1">{g.desc}</div>
                  </div>
                </div>
                <span className="text-[11px] text-muted-foreground capitalize">{g.status}</span>
              </div>
            ))}
          </div>
          {/* flat phases fallback */}
          {display.groups.length === 0 && (
            <div className="mt-4 flex flex-wrap gap-1">
              {display.phases.map(p => (
                <span key={p} className={cn('text-[11px] px-2 py-0.5 rounded-full border capitalize', display.current_phase === p ? 'bg-primary text-primary-foreground border-primary' : 'bg-muted text-muted-foreground')}>{p}</span>
              ))}
            </div>
          )}
        </div>

        {/* ACTIVE ENGINE */}
        <div className="rounded-xl border bg-card p-4 lg:col-span-2">
          <h3 className="text-sm font-semibold flex items-center gap-2 mb-3"><Zap className="h-4 w-4 text-amber-500" /> ACTIVE ENGINE</h3>
          {activeEngine ? (
            <div className="rounded-lg border bg-muted/20 p-4">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-medium">{activeEngine.id}</span>
                <span className={cn('text-xs px-2 py-0.5 rounded-full border', activeEngine.status === 'running' ? 'bg-primary/10 text-primary border-primary/20' : 'bg-muted')}>{activeEngine.status} {activeEngine.progress}%</span>
              </div>
              <div className="h-1.5 rounded-full bg-muted overflow-hidden mt-3">
                <div className="h-full bg-primary transition-all duration-500" style={{ width: `${activeEngine.progress}%` }} />
              </div>
              <div className="grid grid-cols-3 gap-3 mt-3 text-xs">
                <div><div className="text-muted-foreground">Findings</div><div className="font-semibold">{activeEngine.findings}</div></div>
                <div><div className="text-muted-foreground">Phase</div><div className="font-mono">{activeEngine.phase}</div></div>
                <div><div className="text-muted-foreground">Duration</div><div>—</div></div>
              </div>
            </div>
          ) : (
            <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
              {isDone ? 'All engines completed — ready for Results' : isFailed ? 'Validation stopped' : 'Waiting for engine…'}
            </div>
          )}

          {/* Engine grid */}
          <div className="mt-4">
            <div className="text-xs font-medium mb-2">Engines timeline</div>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {display.engines.map(e => (
                <div key={e.id} className={cn('rounded-lg border px-2.5 py-2 flex items-center justify-between text-xs', e.status === 'running' ? 'bg-primary/5 border-primary/30' : e.status === 'completed' ? 'bg-emerald-50/50 dark:bg-emerald-950/20' : e.status === 'failed' ? 'bg-destructive/5 border-destructive/20' : 'bg-card')}>
                  <span className="flex items-center gap-1.5 font-mono truncate">{statusIcon(e.status)} {e.id}</span>
                  <span className="text-[11px] text-muted-foreground">{e.progress}%</span>
                </div>
              ))}
              {display.engines.length === 0 && <span className="text-xs text-muted-foreground col-span-3">No engines — mock run</span>}
            </div>
          </div>
        </div>
      </div>

      {/* LIVE EVENTS */}
      <div className="rounded-xl border bg-card p-4">
        <h3 className="text-sm font-semibold flex items-center gap-2 mb-3"><Activity className="h-4 w-4 text-primary" /> LIVE EVENTS <span className={cn('ml-2 h-2 w-2 rounded-full', wsConnected ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500')} /></h3>
        <div className="rounded-lg bg-black text-green-400 font-mono text-xs p-3 h-48 overflow-auto border">
          {display.live_events.length === 0 ? <div className="text-muted-foreground">No events yet…</div> : display.live_events.map((ev, i) => (
            <div key={i} className="flex gap-2 py-0.5">
              <span className="text-muted-foreground shrink-0">{new Date(ev.ts).toLocaleTimeString()}</span>
              <span className={cn(ev.type.includes('failed') ? 'text-red-400' : ev.type.includes('completed') ? 'text-emerald-400' : ev.type.includes('finding') ? 'text-amber-300' : 'text-green-400')}>{ev.type}</span>
              <span className="text-green-300">{ev.message}</span>
            </div>
          ))}
        </div>
        <div className="flex gap-2 mt-3">
          <button onClick={() => refetch()} className="text-xs px-3 py-1.5 rounded border hover:bg-muted">Refresh</button>
          {isDone && <Link to={`/validations/${id}/results`} className="text-xs px-3 py-1.5 rounded bg-primary text-primary-foreground inline-flex items-center gap-1">Results <ArrowRight className="h-3 w-3" /></Link>}
        </div>
      </div>
    </div>
  )
}
