import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, RefreshCw, Search, ShieldAlert } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { useAuthStore } from '@/stores/authStore'
import { cn } from '@/utils/cn'

type EventStatus = 'new' | 'investigating' | 'resolved' | 'false_positive'
type SecurityEvent = {
  id: string
  event_type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  status: EventStatus
  title: string
  description: string
  source_ip: string | null
  target_user_email: string | null
  assigned_to_id: string | null
  resolved_at: string | null
  resolution_notes: string
  created_at: string
}

type EventList = { items: SecurityEvent[]; total: number; limit: number; offset: number }

const severityStyle: Record<SecurityEvent['severity'], string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-600',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-600',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-600',
  low: 'border-sky-500/40 bg-sky-500/10 text-sky-600',
}

export const SecurityEvents = () => {
  const queryClient = useQueryClient()
  const user = useAuthStore(state => state.user)
  const [status, setStatus] = useState<EventStatus | ''>('')
  const [resolution, setResolution] = useState<Record<string, string>>({})
  const canRespond = ['super_admin', 'admin', 'security_manager', 'security_analyst'].includes(user?.role ?? '')
  const query = useQuery<EventList>({
    queryKey: ['security-events', status],
    queryFn: () => apiHelpers.get<EventList>(`/security-events?limit=100${status ? `&status=${status}` : ''}`),
  })
  const transition = useMutation({
    mutationFn: ({ id, next, notes = '' }: { id: string; next: EventStatus; notes?: string }) =>
      apiHelpers.post<SecurityEvent>(`/security-events/${id}/transition`, { status: next, resolution_notes: notes }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['security-events'] }),
  })
  const items = useMemo(() => query.data?.items ?? [], [query.data])

  return <div className="space-y-5 pb-10">
    <header className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
      <div><div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.16em] text-primary"><ShieldAlert className="h-4 w-4"/>Detection response</div><h1 className="mt-2 text-3xl font-semibold">Security Events</h1><p className="mt-2 text-sm text-muted-foreground">Tenant-scoped detections with durable investigation, resolution, and audit evidence.</p></div>
      <div className="flex items-center gap-2"><select value={status} onChange={event => setStatus(event.target.value as EventStatus | '')} className="h-10 rounded-xl border bg-background px-3 text-sm"><option value="">All states</option><option value="new">New</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select><button type="button" onClick={() => query.refetch()} className="rounded-xl border p-2.5" aria-label="Refresh security events"><RefreshCw className={cn('h-4 w-4', query.isFetching && 'animate-spin')}/></button></div>
    </header>

    {query.isLoading ? <div className="rounded-2xl border p-14 text-center text-sm text-muted-foreground"><RefreshCw className="mx-auto mb-3 h-5 w-5 animate-spin"/>Loading persisted security events…</div> : query.isError ? <div className="rounded-2xl border border-destructive/30 bg-destructive/10 p-8 text-center"><AlertTriangle className="mx-auto h-7 w-7 text-destructive"/><h2 className="mt-3 font-semibold">Security events unavailable</h2><p className="mt-1 text-sm text-muted-foreground">The authoritative API failed. No synthetic events are displayed.</p><button type="button" onClick={() => query.refetch()} className="mt-4 rounded-xl border px-4 py-2 text-sm">Retry</button></div> : items.length === 0 ? <div className="rounded-2xl border p-14 text-center"><CheckCircle2 className="mx-auto h-8 w-8 text-emerald-500"/><h2 className="mt-3 font-semibold">No security events in this scope</h2></div> : <div className="space-y-3">{items.map(item => {
      const terminal = item.status === 'resolved' || item.status === 'false_positive'
      return <article key={item.id} className="rounded-2xl border bg-card p-5 shadow-sm">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className={cn('rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase', severityStyle[item.severity])}>{item.severity}</span><span className="rounded-full border px-2.5 py-1 text-[11px] capitalize">{item.status.replace('_', ' ')}</span><span className="font-mono text-[11px] text-muted-foreground">{item.event_type}</span></div><h2 className="mt-3 text-lg font-semibold">{item.title}</h2><p className="mt-1 text-sm text-muted-foreground">{item.description}</p><div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted-foreground"><span>Source: <strong className="font-mono text-foreground">{item.source_ip ?? 'unknown'}</strong></span><span>Target: <strong className="text-foreground">{item.target_user_email ?? 'unattributed'}</strong></span><span>{new Date(item.created_at).toLocaleString()}</span></div>{terminal && item.resolution_notes && <div className="mt-4 rounded-xl border bg-muted/20 p-3 text-sm"><span className="font-semibold">Resolution evidence:</span> {item.resolution_notes}</div>}</div>
          {canRespond && !terminal && <div className="w-full shrink-0 space-y-2 lg:w-96">{item.status === 'new' ? <button type="button" disabled={transition.isPending} onClick={() => transition.mutate({ id:item.id, next:'investigating' })} className="w-full rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50"><Search className="me-2 inline h-4 w-4"/>Start investigation</button> : <><textarea value={resolution[item.id] ?? ''} onChange={event => setResolution(current => ({ ...current, [item.id]:event.target.value }))} placeholder="Required resolution evidence and actions taken" className="min-h-24 w-full rounded-xl border bg-background p-3 text-sm"/><div className="grid grid-cols-2 gap-2"><button type="button" disabled={transition.isPending || !(resolution[item.id] ?? '').trim()} onClick={() => transition.mutate({ id:item.id, next:'resolved', notes:resolution[item.id] })} className="rounded-xl bg-emerald-600 px-3 py-2 text-sm font-semibold text-white disabled:opacity-40">Resolve</button><button type="button" disabled={transition.isPending || !(resolution[item.id] ?? '').trim()} onClick={() => transition.mutate({ id:item.id, next:'false_positive', notes:resolution[item.id] })} className="rounded-xl border px-3 py-2 text-sm font-semibold disabled:opacity-40">False positive</button></div></>}</div>}
        </div>{transition.isError && <p className="mt-3 text-xs text-destructive">The transition was rejected; refresh to inspect the authoritative current state.</p>}
      </article>
    })}</div>}
    {query.data && <div className="text-end text-xs text-muted-foreground">{query.data.total} persisted event{query.data.total === 1 ? '' : 's'}</div>}
  </div>
}
