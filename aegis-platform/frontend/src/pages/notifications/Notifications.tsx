import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, AlertTriangle, Bell, CheckCircle2, FileText, RefreshCw } from 'lucide-react'
import { apiHelpers, createWebSocket } from '@/services/api'
import { cn } from '@/utils/cn'
import { useLanguageStore } from '@/stores/languageStore'

type NotificationItem = {
  id: string
  channel: string
  event_type: string
  payload: Record<string, unknown>
  status: string
  attempts: number
  last_error?: string | null
  sent_at?: string | null
  created_at: string
}

const iconFor = (type: string) => {
  const value = type.toLowerCase()
  if (value.includes('finding') || value.includes('risk')) return AlertTriangle
  if (value.includes('report')) return FileText
  if (value.includes('validation')) return Activity
  return Bell
}

export const Notifications = () => {
  const t = useLanguageStore(s => s.t)
  const [liveEvents, setLiveEvents] = useState<Array<Record<string, unknown>>>([])
  const query = useQuery<NotificationItem[]>({
    queryKey: ['notifications'],
    queryFn: () => apiHelpers.get<NotificationItem[]>('/enterprise/notifications?limit=100'),
  })

  useEffect(() => {
    const ws = createWebSocket('/ws/notifications')
    ws.onmessage = event => {
      try {
        const parsed = JSON.parse(event.data) as Record<string, unknown>
        setLiveEvents(current => [parsed, ...current].slice(0, 20))
        void query.refetch()
      } catch {
        // Ignore malformed external events; no local event is synthesized.
      }
    }
    return () => ws.close()
  }, [query.refetch])

  const items = useMemo(() => query.data ?? [], [query.data])

  return (
    <div className="space-y-6 pb-10">
      <section className="enterprise-card rounded-3xl p-6 md:p-8">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.16em] text-primary"><Bell className="h-4 w-4" />{t('Notifications')}</div>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight">{t('Notification center')}</h1>
            <p className="mt-2 text-sm text-muted-foreground">{t('Persisted notifications from the platform event pipeline. Live events are received from the authenticated WebSocket channel.')}</p>
          </div>
          <button type="button" onClick={() => query.refetch()} disabled={query.isFetching} className="inline-flex items-center gap-2 rounded-xl border bg-card px-4 py-2.5 text-sm font-semibold hover:bg-accent"><RefreshCw className={cn('h-4 w-4', query.isFetching && 'animate-spin')} />{t('Refresh')}</button>
        </div>
      </section>

      {query.isLoading && <div className="enterprise-card rounded-2xl p-12 text-center text-sm text-muted-foreground">{t('Loading...')}</div>}
      {query.isError && <div className="enterprise-card rounded-2xl p-12 text-center"><AlertTriangle className="mx-auto h-8 w-8 text-destructive"/><h2 className="mt-3 font-semibold">{t('Unable to load notifications')}</h2><p className="mt-1 text-sm text-muted-foreground">{t('The notifications API returned an error. No local or synthetic notifications are displayed.')}</p><button type="button" onClick={() => query.refetch()} className="mt-4 rounded-xl border px-4 py-2 text-sm font-medium">{t('Retry')}</button></div>}

      {!query.isLoading && !query.isError && (
        <section className="enterprise-card overflow-hidden rounded-2xl">
          {items.length === 0 ? <div className="p-16 text-center"><CheckCircle2 className="mx-auto h-8 w-8 text-muted-foreground"/><h2 className="mt-3 font-medium">{t('No notifications available')}</h2></div> : <div className="divide-y divide-border/70">{items.map(item => { const Icon = iconFor(item.event_type); return <div key={item.id} className="flex gap-4 px-5 py-4 hover:bg-muted/20"><div className="mt-0.5 rounded-xl border bg-muted/30 p-2 text-primary"><Icon className="h-4 w-4"/></div><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><span className="font-medium">{item.event_type}</span><span className="rounded-full border px-2 py-0.5 text-[10px] capitalize">{item.status}</span><span className="text-[11px] text-muted-foreground">{item.channel}</span></div><div className="mt-1 text-xs text-muted-foreground">{new Date(item.created_at).toLocaleString()}</div>{item.last_error && <div className="mt-2 rounded-lg border border-destructive/20 bg-destructive/5 px-3 py-2 text-xs text-destructive">{item.last_error}</div>}</div><div className="text-xs text-muted-foreground">{item.attempts}</div></div> })}</div>}
        </section>
      )}

      {liveEvents.length > 0 && <section className="enterprise-card rounded-2xl p-5"><div className="mb-3"><h2 className="enterprise-section-title">{t('Live events')}</h2><p className="enterprise-muted mt-1">{t('Received during this session')}</p></div><div className="space-y-2">{liveEvents.map((event,index)=><pre key={index} className="overflow-auto rounded-xl border bg-background/40 p-3 text-[11px] text-muted-foreground">{JSON.stringify(event,null,2)}</pre>)}</div></section>}
    </div>
  )
}
