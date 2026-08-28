import { useQuery } from '@tanstack/react-query'
import { Activity, ArrowUpRight, CheckCircle2, CircleAlert, ShieldCheck, TicketCheck } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { cn } from '@/utils/cn'

interface Metric { name: string; value: number | null; percentage?: number | null; trend?: string; measured?: boolean }
interface LiveDashboard { posture: { score: number; rating: string; metrics: Metric[]; recommendations: string[]; trend: { direction: string; change_rate: number } } }
interface Integration { id: string; configured: boolean }

export const LivePosturePanel = () => {
  const query = useQuery({ queryKey: ['dashboard-live'], queryFn: () => apiHelpers.get<LiveDashboard>('/dashboard/live'), refetchInterval: 15000 })
  const integrationQuery = useQuery({ queryKey: ['orchestration-integrations'], queryFn: () => apiHelpers.get<{ providers: Integration[] }>('/orchestration/integrations'), refetchInterval: 30000 })
  if (query.isLoading) return <div className="aegis-surface h-64 animate-pulse bg-muted/30" />
  if (query.isError || !query.data) return <div className="aegis-surface p-5"><div className="flex items-center gap-2 text-sm font-semibold"><CircleAlert className="h-4 w-4 text-destructive" />Live posture unavailable</div><p className="mt-2 text-xs text-muted-foreground">The dashboard could not retrieve the evidence-driven posture state.</p></div>
  const posture = query.data.posture
  const integrations = integrationQuery.data?.providers ?? []
  return <section className="aegis-surface p-5">
    <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-center"><div><div className="aegis-kicker flex items-center gap-2 text-primary"><Activity className="h-3.5 w-3.5" />Live assurance state</div><div className="mt-1 flex items-end gap-3"><span className="text-3xl font-bold tracking-tight">{Math.round(posture.score)}</span><span className="pb-1 text-xs text-muted-foreground">/ 100 · {posture.rating}</span><span className="pb-1 text-xs font-medium text-muted-foreground">{posture.trend.direction} ({posture.trend.change_rate >= 0 ? '+' : ''}{posture.trend.change_rate})</span></div></div><div className="flex items-center gap-2 rounded-xl border px-3 py-2 text-xs"><ShieldCheck className="h-4 w-4 text-primary" />Measured from validation evidence</div></div>
    <div className="mt-5 grid gap-2 sm:grid-cols-2 lg:grid-cols-5">{posture.metrics.map((metric) => <div key={metric.name} className="rounded-xl border bg-muted/20 p-3"><div className="truncate text-[11px] font-medium text-muted-foreground">{metric.name}</div><div className="mt-2 flex items-baseline justify-between"><span className={cn('text-lg font-bold', metric.measured === false && 'text-muted-foreground')}>{metric.value == null ? 'N/M' : Math.round(metric.value)}</span><span className="text-[10px] uppercase tracking-wider text-muted-foreground">{metric.measured === false ? 'not measured' : metric.trend}</span></div></div>)}</div>
    <div className="mt-5 grid gap-4 lg:grid-cols-[1fr_auto] lg:items-end"><div><div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Priority recommendations</div><div className="mt-2 space-y-1.5">{posture.recommendations.slice(0, 3).map((item) => <div key={item} className="flex items-start gap-2 text-xs text-muted-foreground"><CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary" />{item}</div>)}</div></div><div className="space-y-2"><div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground"><TicketCheck className="h-3.5 w-3.5" />Remediation integrations</div><div className="flex flex-wrap gap-1.5">{integrations.map((item) => <span key={item.id} className={cn('rounded-full border px-2 py-1 text-[10px] font-semibold uppercase', !item.configured && 'text-muted-foreground')}>{item.id}: {item.configured ? 'ready' : 'not configured'}</span>)}</div><a href="/posture" className="inline-flex w-full items-center justify-center gap-1 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-accent">Open posture <ArrowUpRight className="h-3.5 w-3.5" /></a></div></div>
  </section>
}
