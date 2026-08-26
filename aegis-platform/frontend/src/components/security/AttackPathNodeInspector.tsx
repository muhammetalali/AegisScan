import { AlertTriangle, ArrowDown, ArrowUp, ExternalLink, ShieldCheck } from 'lucide-react'
import type { AttackPathEdge, AttackPathNode } from './AttackPathGraph'

export function AttackPathNodeInspector({ node, nodes, edges, onOpen }: { node: AttackPathNode | null; nodes: AttackPathNode[]; edges: AttackPathEdge[]; onOpen?: (node: AttackPathNode) => void }) {
  if (!node) return <aside className="rounded-2xl border bg-card p-5 text-sm text-muted-foreground">Select a node to inspect its security context.</aside>

  const incoming = edges.filter((edge) => edge.to === node.id).map((edge) => nodes.find((item) => item.id === edge.from)).filter(Boolean) as AttackPathNode[]
  const outgoing = edges.filter((edge) => edge.from === node.id).map((edge) => nodes.find((item) => item.id === edge.to)).filter(Boolean) as AttackPathNode[]

  return <aside className="overflow-hidden rounded-2xl border bg-card">
    <header className="border-b p-5"><div className="flex items-start justify-between gap-3"><div><div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">Node intelligence</div><h3 className="mt-1 text-lg font-semibold">{node.label}</h3><p className="mt-1 text-xs text-muted-foreground">{node.meta ?? node.type}</p></div>{node.severity && <span className="inline-flex items-center gap-1 rounded-full border border-red-500/30 bg-red-500/10 px-2 py-1 text-[10px] font-bold uppercase"><AlertTriangle className="h-3 w-3" /> {node.severity}</span>}</div></header>
    <div className="space-y-5 p-5">
      <div className="grid grid-cols-2 gap-2"><div className="rounded-xl border p-3"><div className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground"><ArrowUp className="h-3 w-3" /> Incoming</div><div className="mt-1 text-xl font-semibold">{incoming.length}</div></div><div className="rounded-xl border p-3"><div className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground"><ArrowDown className="h-3 w-3" /> Outgoing</div><div className="mt-1 text-xl font-semibold">{outgoing.length}</div></div></div>
      <div><div className="mb-2 text-xs font-semibold">Path context</div><div className="space-y-2">{incoming.map((item) => <div key={`in-${item.id}`} className="rounded-lg border px-3 py-2 text-xs"><span className="text-muted-foreground">From</span><div className="font-medium">{item.label}</div></div>)}{outgoing.map((item) => <div key={`out-${item.id}`} className="rounded-lg border px-3 py-2 text-xs"><span className="text-muted-foreground">To</span><div className="font-medium">{item.label}</div></div>)}</div></div>
      {node.type === 'finding' && <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-3"><div className="flex items-center gap-2 text-xs font-semibold"><ShieldCheck className="h-4 w-4 text-emerald-600" /> Validation context</div><p className="mt-1 text-[11px] leading-5 text-muted-foreground">Use the finding investigation to inspect evidence and re-validation history.</p></div>}
      {onOpen && <button type="button" onClick={() => onOpen(node)} className="flex w-full items-center justify-center gap-2 rounded-xl border bg-background px-3 py-2.5 text-xs font-semibold hover:bg-muted"><ExternalLink className="h-3.5 w-3.5" /> Open investigation</button>}
    </div>
  </aside>
}
