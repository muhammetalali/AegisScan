import { useMemo, useState } from 'react'
import { CheckCircle2, CircleDot, FileSearch, Link2, ShieldAlert, ShieldCheck } from 'lucide-react'
import { cn } from '@/utils/cn'

export type EvidenceGraphNode = { id: string; label: string; type: 'asset' | 'finding' | 'evidence' | 'validation' | 'endpoint'; meta?: string; status?: 'verified' | 'unverified' | 'failed' }
export type EvidenceGraphEdge = { from: string; to: string; label?: string }
const iconFor = { asset: ShieldCheck, finding: ShieldAlert, evidence: FileSearch, validation: CheckCircle2, endpoint: CircleDot }
const toneFor = { asset: 'border-violet-500/40 bg-violet-500/10', finding: 'border-red-500/50 bg-red-500/10', evidence: 'border-cyan-500/40 bg-cyan-500/10', validation: 'border-emerald-500/40 bg-emerald-500/10', endpoint: 'border-sky-500/40 bg-sky-500/10' }

export function EvidenceGraph({ nodes, edges, onSelect }: { nodes: EvidenceGraphNode[]; edges: EvidenceGraphEdge[]; onSelect?: (node: EvidenceGraphNode) => void }) {
  const [selected, setSelected] = useState(nodes[0]?.id ?? null)
  const selectedNode = nodes.find((node) => node.id === selected)
  const connected = useMemo(() => { const set = new Set<string>(); if (selected) set.add(selected); edges.forEach((edge) => { if (edge.from === selected) set.add(edge.to); if (edge.to === selected) set.add(edge.from) }); return set }, [edges, selected])
  const groups = useMemo(() => { const order: EvidenceGraphNode['type'][] = ['asset', 'endpoint', 'finding', 'evidence', 'validation']; return order.map((type) => nodes.filter((node) => node.type === type)).filter(Boolean).filter((group) => group.length) }, [nodes])
  const positions = useMemo(() => { const result = new Map<string, { x: number; y: number }>(); groups.forEach((group, gi) => group.forEach((node, ni) => result.set(node.id, { x: 90 + gi * 195, y: 72 + ni * 92 }))); return result }, [groups])
  const select = (node: EvidenceGraphNode) => { setSelected(node.id); onSelect?.(node) }

  return <section className="overflow-hidden rounded-2xl border bg-card">
    <header className="flex flex-wrap items-center justify-between gap-3 border-b px-5 py-4"><div><div className="flex items-center gap-2 font-semibold"><Link2 className="h-4 w-4 text-primary" /> Evidence Graph</div><p className="mt-1 text-xs text-muted-foreground">Trace how evidence proves a finding across assets and validation events.</p></div><div className="text-[11px] text-muted-foreground">{nodes.length} nodes · {edges.length} relationships</div></header>
    <div className="relative overflow-auto bg-[radial-gradient(circle_at_center,hsl(var(--muted)/.45)_1px,transparent_1px)] [background-size:18px_18px] p-5">
      <div className="relative min-h-[360px] min-w-[1100px]">
        <svg className="pointer-events-none absolute inset-0 h-full w-full" viewBox="0 0 1100 360" preserveAspectRatio="none" aria-hidden="true">
          <defs><marker id="evidence-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" /></marker></defs>
          {edges.map((edge) => { const a = positions.get(edge.from); const b = positions.get(edge.to); if (!a || !b) return null; const active = edge.from === selected || edge.to === selected; const mid = (a.x + b.x) / 2; return <g key={`${edge.from}-${edge.to}`} className={cn('transition-opacity', selected && !active && 'opacity-15')}><path d={`M ${a.x + 78} ${a.y + 30} C ${mid} ${a.y + 30}, ${mid} ${b.y + 30}, ${b.x - 78} ${b.y + 30}`} fill="none" stroke="currentColor" strokeWidth={active ? 2.5 : 1.5} strokeDasharray={active ? '7 5' : undefined} markerEnd="url(#evidence-arrow)" className={active ? 'text-primary' : 'text-muted-foreground/40'} /><text x={mid} y={(a.y + b.y) / 2 + 24} textAnchor="middle" className="fill-muted-foreground text-[9px]">{edge.label ?? ''}</text></g> })}
        </svg>
        {groups.map((group) => group.map((node) => { const p = positions.get(node.id)!; const Icon = iconFor[node.type]; const active = node.id === selected; const visible = !selected || connected.has(node.id); return <button key={node.id} type="button" aria-pressed={active} onClick={() => select(node)} style={{ left: p.x - 78, top: p.y }} className={cn('absolute z-10 w-[156px] rounded-xl border p-3 text-left shadow-sm transition-all duration-200 hover:-translate-y-0.5 hover:shadow-md', toneFor[node.type], !visible && 'opacity-15 saturate-0', active && 'ring-2 ring-primary/60 shadow-md')}><div className="flex items-start gap-2"><span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border bg-background/70"><Icon className="h-3.5 w-3.5" /></span><span className="min-w-0"><span className="block truncate text-xs font-semibold">{node.label}</span><span className="mt-0.5 block truncate text-[10px] text-muted-foreground">{node.meta ?? node.type}</span></span></div>{node.status && <span className={cn('mt-2 inline-flex rounded-full border px-2 py-0.5 text-[9px] font-semibold uppercase', node.status === 'verified' && 'border-emerald-500/30 text-emerald-600', node.status === 'failed' && 'border-red-500/30 text-red-600')}>{node.status}</span>}</button> }))}
      </div>
    </div>
    {selectedNode && <footer className="border-t bg-muted/20 px-5 py-4"><div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">Evidence context</div><div className="mt-1 flex flex-wrap items-center justify-between gap-3"><div><div className="font-medium">{selectedNode.label}</div><div className="text-xs text-muted-foreground">{selectedNode.meta ?? selectedNode.type}</div></div><div className="text-xs text-muted-foreground">{edges.filter((edge) => edge.from === selectedNode.id || edge.to === selectedNode.id).length} relationships</div></div></footer>}
  </section>
}
