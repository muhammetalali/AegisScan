import { useMemo, useState } from 'react'
import { CheckCircle2, CircleDot, FileSearch, Link2, ShieldAlert, ShieldCheck } from 'lucide-react'
import { cn } from '@/utils/cn'

export type EvidenceGraphNode = {
  id: string
  label: string
  type: 'asset' | 'finding' | 'evidence' | 'validation' | 'endpoint'
  meta?: string
  status?: 'verified' | 'unverified' | 'failed'
}
export type EvidenceGraphEdge = { from: string; to: string; label?: string }

const iconFor = { asset: ShieldCheck, finding: ShieldAlert, evidence: FileSearch, validation: CheckCircle2, endpoint: CircleDot }
const toneFor = { asset: 'border-violet-500/40 bg-violet-500/10', finding: 'border-red-500/50 bg-red-500/10', evidence: 'border-cyan-500/40 bg-cyan-500/10', validation: 'border-emerald-500/40 bg-emerald-500/10', endpoint: 'border-sky-500/40 bg-sky-500/10' }

export function EvidenceGraph({ nodes, edges, onSelect }: { nodes: EvidenceGraphNode[]; edges: EvidenceGraphEdge[]; onSelect?: (node: EvidenceGraphNode) => void }) {
  const [selected, setSelected] = useState<string | null>(nodes[0]?.id ?? null)
  const selectedNode = nodes.find((node) => node.id === selected)
  const connected = useMemo(() => new Set(edges.flatMap((edge) => edge.from === selected ? [edge.to] : edge.to === selected ? [edge.from] : []).concat(selected ? [selected] : [])), [edges, selected])
  const select = (node: EvidenceGraphNode) => { setSelected(node.id); onSelect?.(node) }

  const groups = useMemo(() => {
    const order: EvidenceGraphNode['type'][] = ['asset', 'endpoint', 'finding', 'evidence', 'validation']
    return order.map((type) => nodes.filter((node) => node.type === type)).filter((group) => group.length)
  }, [nodes])

  return <section className="overflow-hidden rounded-2xl border bg-card">
    <header className="flex flex-wrap items-center justify-between gap-3 border-b px-5 py-4"><div><div className="flex items-center gap-2 font-semibold"><Link2 className="h-4 w-4 text-primary" /> Evidence Graph</div><p className="mt-1 text-xs text-muted-foreground">Trace how evidence proves a finding across assets and validation events.</p></div><div className="text-[11px] text-muted-foreground">{nodes.length} nodes · {edges.length} relationships</div></header>
    <div className="overflow-x-auto p-5"><div className="flex min-w-[920px] items-stretch gap-3">
      {groups.map((group, index) => <div key={group[0].type} className="relative flex min-w-[175px] flex-1 flex-col justify-center gap-3">{group.map((node) => { const Icon = iconFor[node.type]; const active = node.id === selected; const visible = !selected || connected.has(node.id); return <button key={node.id} type="button" aria-pressed={active} onClick={() => select(node)} className={cn('relative rounded-xl border p-3 text-left shadow-sm transition-all hover:-translate-y-0.5 hover:shadow-md', toneFor[node.type], !visible && 'opacity-20 saturate-0', active && 'ring-2 ring-primary/60 shadow-md')}><div className="flex items-start gap-3"><span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border bg-background/70"><Icon className="h-4 w-4" /></span><span className="min-w-0 flex-1"><span className="block truncate text-sm font-semibold">{node.label}</span><span className="mt-0.5 block truncate text-[11px] text-muted-foreground">{node.meta ?? node.type}</span></span></div>{node.status && <span className={cn('mt-2 inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase', node.status === 'verified' && 'border-emerald-500/30 text-emerald-600', node.status === 'failed' && 'border-red-500/30 text-red-600')}>{node.status}</span>}</button>})}{index < groups.length - 1 && <div className="pointer-events-none absolute -right-3 top-1/2 z-10 hidden -translate-y-1/2 md:block text-muted-foreground">→</div>}</div>)}
    </div></div>
    {selectedNode && <footer className="border-t bg-muted/20 px-5 py-4"><div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">Evidence context</div><div className="mt-1 flex flex-wrap items-center justify-between gap-3"><div><div className="font-medium">{selectedNode.label}</div><div className="text-xs text-muted-foreground">{selectedNode.meta ?? selectedNode.type}</div></div><div className="text-xs text-muted-foreground">{edges.filter((edge) => edge.from === selectedNode.id || edge.to === selectedNode.id).length} relationships</div></div></footer>}
  </section>
}
