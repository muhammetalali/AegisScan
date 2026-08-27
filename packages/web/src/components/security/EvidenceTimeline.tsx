import { useMemo, useState } from 'react'
import { CheckCircle2, ChevronRight, Clock3, Copy, FileSearch, ShieldCheck, Terminal, XCircle } from 'lucide-react'
import { cn } from '@/utils/cn'

export type EvidenceEvent = {
  id: string
  timestamp: string
  title: string
  source?: string
  engine?: string
  type?: 'request' | 'response' | 'finding' | 'validation' | 'system'
  status?: 'verified' | 'warning' | 'failed'
  summary?: string
  payload?: string
}

const iconFor = { request: Terminal, response: ChevronRight, finding: FileSearch, validation: ShieldCheck, system: Clock3 }

export function EvidenceTimeline({ events, onSelect }: { events: EvidenceEvent[]; onSelect?: (event: EvidenceEvent) => void }) {
  const [selected, setSelected] = useState(events[0]?.id ?? null)
  const selectedEvent = useMemo(() => events.find((event) => event.id === selected), [events, selected])

  const select = (event: EvidenceEvent) => { setSelected(event.id); onSelect?.(event) }

  return (
    <section className="overflow-hidden rounded-2xl border bg-card">
      <header className="border-b px-5 py-4">
        <div className="flex items-center gap-2 font-semibold"><FileSearch className="h-4 w-4 text-primary" /> Evidence Timeline</div>
        <p className="mt-1 text-xs text-muted-foreground">Chronological chain of validation evidence and security events.</p>
      </header>
      <div className="grid lg:grid-cols-[minmax(0,1.2fr)_minmax(280px,.8fr)]">
        <div className="divide-y">
          {events.length === 0 && <div className="p-8 text-center text-sm text-muted-foreground">No evidence events available.</div>}
          {events.map((event) => {
            const Icon = iconFor[event.type ?? 'system']
            const active = event.id === selected
            return <button key={event.id} type="button" onClick={() => select(event)} aria-pressed={active} className={cn('relative flex w-full gap-4 px-5 py-4 text-left transition hover:bg-muted/40', active && 'bg-primary/5')}>
              <div className="relative flex flex-col items-center"><span className={cn('grid h-9 w-9 place-items-center rounded-full border bg-background', active && 'border-primary/50 text-primary')}><Icon className="h-4 w-4" /></span><span className="absolute top-10 bottom-[-18px] w-px bg-border last:hidden" /></div>
              <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><span className="text-[11px] font-medium text-muted-foreground">{event.timestamp}</span>{event.status === 'verified' && <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-600"><CheckCircle2 className="h-3 w-3" /> verified</span>}{event.status === 'failed' && <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-destructive"><XCircle className="h-3 w-3" /> failed</span>}</div><div className="mt-1 font-medium">{event.title}</div><div className="mt-0.5 truncate text-xs text-muted-foreground">{event.summary ?? 'Security evidence event'}</div>{(event.source || event.engine) && <div className="mt-2 flex gap-2 text-[10px] text-muted-foreground"><span>{event.source}</span>{event.engine && <><span>·</span><span>{event.engine}</span></>}</div>}</div>
            </button>
          })}
        </div>
        <aside className="border-t bg-muted/10 p-5 lg:border-l lg:border-t-0">
          <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">Evidence detail</div>
          {selectedEvent ? <><h3 className="mt-2 font-semibold">{selectedEvent.title}</h3><p className="mt-1 text-xs leading-5 text-muted-foreground">{selectedEvent.summary ?? 'No additional summary was provided.'}</p>{selectedEvent.payload && <div className="mt-4 overflow-hidden rounded-xl border bg-background"><div className="flex items-center justify-between border-b px-3 py-2"><span className="text-[10px] font-semibold uppercase tracking-wider">Payload</span><button type="button" title="Copy payload" aria-label="Copy payload" onClick={() => navigator.clipboard?.writeText(selectedEvent.payload ?? '')} className="rounded-md p-1.5 hover:bg-muted"><Copy className="h-3.5 w-3.5" /></button></div><pre className="max-h-64 overflow-auto p-3 text-[11px] leading-5">{selectedEvent.payload}</pre></div>}<div className="mt-4 grid grid-cols-2 gap-2 text-xs"><div className="rounded-lg border p-3"><div className="text-muted-foreground">Source</div><div className="mt-1 font-medium">{selectedEvent.source ?? '—'}</div></div><div className="rounded-lg border p-3"><div className="text-muted-foreground">Engine</div><div className="mt-1 font-medium">{selectedEvent.engine ?? '—'}</div></div></div></> : <div className="mt-8 text-center text-xs text-muted-foreground">Select an evidence event to inspect it.</div>}
        </aside>
      </div>
    </section>
  )
}
