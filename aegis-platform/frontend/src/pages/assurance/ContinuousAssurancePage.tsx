import { useQuery } from '@tanstack/react-query'
import { CalendarClock, RefreshCw, ShieldCheck, ShieldX } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { apiHelpers } from '@/services/api'
import { ContinuousAssuranceFabric, type AssuranceCheckpoint } from '@/components/security/ContinuousAssuranceFabric'

export const ContinuousAssurancePage = () => {
  const navigate = useNavigate()
  const query = useQuery({ queryKey: ['continuous-assurance'], queryFn: async () => {
    const [schedulesPayload, trends, summary] = await Promise.all([
      apiHelpers.get<any>('/enterprise/continuous-assurance'),
      apiHelpers.get<any>('/dashboard/trends?days=30'),
      apiHelpers.get<any>('/dashboard/summary'),
    ])
    const schedules = Array.isArray(schedulesPayload) ? schedulesPayload : schedulesPayload?.results ?? []
    const rows = Array.isArray(trends) ? trends : trends?.results ?? trends?.items ?? []
    const checkpoints: AssuranceCheckpoint[] = rows.map((row: any, index: number) => ({
      id: String(row.id ?? row.date ?? index),
      label: String(row.label ?? row.date ?? `Checkpoint ${index + 1}`).slice(0, 24),
      timestamp: String(row.date ?? row.timestamp ?? '—'),
      state: row.state ?? (index === rows.length - 1 ? 'stable' : 'changed'),
      risk: Number(row.risk ?? Math.max(0, 100 - Number(row.score ?? 0))),
      previousRisk: index > 0 ? Number(rows[index - 1].risk ?? Math.max(0, 100 - Number(rows[index - 1].score ?? 0))) : undefined,
      confidence: Number(row.confidence ?? summary?.confidence ?? 0),
      sources: Number(row.sources ?? summary?.sources ?? 0),
      critical: Number(row.critical ?? 0),
      blastRadius: Number(row.blast_radius ?? 0),
    }))
    return { checkpoints, schedules }
  } })

  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading continuous assurance…</div>
  if (query.error) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Continuous assurance unavailable</h1><p className="mt-2 text-sm text-muted-foreground">Live assurance checkpoints are required for this view.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>

  const schedules = query.data?.schedules ?? []
  return <div className="space-y-5">
    <section className="rounded-2xl border bg-card">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b px-5 py-4">
        <div><h2 className="flex items-center gap-2 font-semibold"><CalendarClock className="h-4 w-4 text-primary" /> Authorized schedules</h2><p className="mt-1 text-xs text-muted-foreground">Live tenant, asset, authorization, and execution lineage from PostgreSQL.</p></div>
        <div className="text-xs font-semibold">{schedules.filter((item: any) => item.enabled).length} active / {schedules.length} total</div>
      </header>
      {schedules.length === 0 ? <div className="p-8 text-center text-sm text-muted-foreground">No continuous assurance schedules are configured for your current tenant access.</div> : <div className="divide-y">{schedules.map((item: any) => {
        const execution = item.latest_execution
        return <article key={item.id} className="grid gap-3 px-5 py-4 md:grid-cols-[minmax(0,1fr)_auto] md:items-center">
          <div className="min-w-0"><div className="flex items-center gap-2">{item.enabled ? <ShieldCheck className="h-4 w-4 text-emerald-600" /> : <ShieldX className="h-4 w-4 text-destructive" />}<h3 className="truncate text-sm font-semibold">{item.project_name} · {item.asset_name ?? 'Unbound asset'}</h3></div><p className="mt-1 text-xs text-muted-foreground">{item.engine} every {item.interval_minutes} minutes · next {item.next_run}</p>{item.disabled_reason && <p className="mt-2 text-xs text-destructive">{item.disabled_reason}</p>}</div>
          <div className="text-left md:text-right"><div className="text-xs font-semibold">{execution?.status ?? 'not run'}</div><div className="mt-1 text-[10px] text-muted-foreground">{execution?.scan_id ? `Scan ${execution.scan_id}` : execution?.scheduled_for ?? 'No durable execution yet'}</div></div>
        </article>
      })}</div>}
    </section>
    <ContinuousAssuranceFabric checkpoints={query.data?.checkpoints ?? []} onOpenPosture={() => navigate('/posture')} onOpenExecutive={() => navigate('/executive')} />
  </div>
}
