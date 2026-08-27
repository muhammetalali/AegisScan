import { useMemo, useState } from 'react'
import { ArrowRight, CircleDot, FileCheck2, Fingerprint, GitBranch, ShieldCheck, Target, X } from 'lucide-react'

export type TraceNodeKind = 'validation' | 'risk' | 'evidence' | 'posture' | 'executive'
export type TraceNode = { id: string; label: string; kind: TraceNodeKind; value?: string | number; detail?: string; confidence?: number; sourceCount?: number }
export type TraceEdge = { from: string; to: string; label?: string }

const kindMeta: Record<TraceNodeKind, { icon: typeof CircleDot; label: string }> = {
  validation: { icon: FileCheck2, label: 'Validation' },
  risk: { icon: Target, label: 'Risk signal' },
  evidence: { icon: Fingerprint, label: 'Evidence' },
  posture: { icon: ShieldCheck, label: 'Posture' },
  executive: { icon: GitBranch, label: 'Executive impact' },
}

export function TraceabilityEvidenceGraph({ nodes, edges }: { nodes: TraceNode[]; edges: TraceEdge[] }) {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const selected = nodes.find((node) => node.id === selectedId)
  const positions = useMemo(() => {
    const byKind = new Map<TraceNodeKind, TraceNode[]>()
    nodes.forEach((node) => { const list = byKind.get(node.kind) ?? []; list.push(node); byKind.set(node.kind, list) })
    const order: TraceNodeKind[] = ['validation', 'risk', 'evidence', 'posture', 'executive']
    const result = new Map<string, { x: number; y: number }>()
    order.forEach((kind, column) => (byKind.get(kind) ?? []).forEach((node, row) => result.set(node.id, { x: 110 + column * 205, y: 95 + row * 105 })))
    return result
  }, [nodes])

  if (!nodes.length) return <section className="rounded-2xl border bg-card p-8 text-center"><CircleDot className="mx-auto h-8 w-8 text-muted-foreground" /><h3 className="mt-3 text-sm font-semibold">Traceability awaiting evidence</h3><p className="mt-1 text-xs text-muted-foreground">The graph will render once validation, evidence, or provenance signals are available.</p></section>

  return <section className="overflow-hidden rounded-2xl border bg-card">
    <header className="flex flex-wrap items-center justify-between gap-4 border-b px-5 py-4">
      <div><div className="flex items-center gap-2 font-semibold"><GitBranch className="h-4 w-4 text-primary" /> Traceability Engine · Interactive Evidence Graph</div><p className="mt-1 text-xs text-muted-foreground">Follow measured security signals from validation provenance to posture and executive impact.</p></div>
      <div className="rounded-lg border px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{nodes.length} nodes · {edges.length} links</div>
    </header>
    <div className="relative min-h-[430px] overflow-auto bg-[radial-gradient(circle_at_20%_20%,hsl(var(--primary)/.08),transparent_35%)] p-5">
      <svg viewBox="0 0 980 410" className="min-w-[900px]" role="img" aria-label="Interactive evidence traceability graph">
        <defs><marker id="trace-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" /></marker></defs>
        {edges.map((edge) => { const a = positions.get(edge.from); const b = positions.get(edge.to); if (!a || !b) return null; return <g key={`${edge.from}-${edge.to}`} className="text-primary/40"><path d={`M ${a.x + 70} ${a.y} C ${a.x + 120} ${a.y}, ${b.x - 120} ${b.y}, ${b.x - 70} ${b.y}`} fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray="5 5" markerEnd="url(#trace-arrow)" /><text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 8} textAnchor="middle" className="fill-muted-foreground text-[10px]">{edge.label ?? 'propagates'}</text></g> })}
        {nodes.map((node) => { const p = positions.get(node.id)!; const Meta = kindMeta[node.kind]; const Icon = Meta.icon; const active = selectedId === node.id; return <g key={node.id} transform={`translate(${p.x - 70},${p.y - 34})`} onClick={() => setSelectedId(node.id)} className="cursor-pointer"><rect width="140" height="68" rx="12" className={active ? 'fill-primary/15 stroke-primary' : 'fill-card stroke-border'} strokeWidth={active ? 2 : 1.5} /><foreignObject width="140" height="68"><div className="flex h-full items-center gap-2 px-3"><Icon className="h-4 w-4 shrink-0 text-primary" /><div className="min-w-0"><div className="truncate text-[10px] font-bold uppercase tracking-wide text-muted-foreground">{Meta.label}</div><div className="truncate text-xs font-semibold">{node.label}</div>{node.value !== undefined && <div className="truncate text-[10px] text-muted-foreground">{node.value}</div>}</div></div></foreignObject></g> })}
      </svg>
    </div>
    {selected && <div className="border-t bg-muted/10 p-5"><div className="flex items-start justify-between gap-4"><div><div className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">Selected provenance node</div><h3 className="mt-1 font-semibold">{selected.label}</h3><p className="mt-1 text-xs text-muted-foreground">{selected.detail ?? 'Measured signal available in the current assurance dataset.'}</p></div><button type="button" onClick={() => setSelectedId(null)} className="rounded-lg border p-2 hover:bg-muted" aria-label="Close node inspector"><X className="h-4 w-4" /></button></div><div className="mt-4 flex flex-wrap gap-2 text-[10px]">{selected.value !== undefined && <span className="rounded-lg border bg-background px-3 py-2 font-semibold">Value: {selected.value}</span>}{selected.confidence !== undefined && <span className="rounded-lg border bg-background px-3 py-2 font-semibold">Confidence: {selected.confidence}%</span>}{selected.sourceCount !== undefined && <span className="rounded-lg border bg-background px-3 py-2 font-semibold">Sources: {selected.sourceCount}</span>}<span className="inline-flex items-center gap-1 rounded-lg border bg-background px-3 py-2 font-semibold"><ArrowRight className="h-3 w-3" /> Trace downstream</span></div></div>}
  </section>
}

export default TraceabilityEvidenceGraph
