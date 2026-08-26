import { useMemo, useState } from 'react'
import { AlertTriangle, Database, Globe2, Maximize2, Minus, Plus, RotateCcw, Server, ShieldAlert, Waypoints } from 'lucide-react'
import { cn } from '@/utils/cn'

export type AttackPathNode = {
  id: string
  label: string
  type: 'entry' | 'asset' | 'service' | 'finding' | 'data'
  severity?: 'critical' | 'high' | 'medium' | 'low'
  meta?: string
}

export type AttackPathEdge = { from: string; to: string; label?: string }

const iconFor = { entry: Globe2, asset: Server, service: Waypoints, finding: ShieldAlert, data: Database }
const toneFor = {
  entry: 'border-sky-500/40 bg-sky-500/10', asset: 'border-violet-500/40 bg-violet-500/10',
  service: 'border-cyan-500/40 bg-cyan-500/10', finding: 'border-red-500/50 bg-red-500/10', data: 'border-amber-500/40 bg-amber-500/10',
}

export function AttackPathGraph({ nodes, edges, onSelect }: { nodes: AttackPathNode[]; edges: AttackPathEdge[]; onSelect?: (node: AttackPathNode) => void }) {
  const [selected, setSelected] = useState<string | null>(nodes[0]?.id ?? null)
  const [scale, setScale] = useState(1)
  const [focusOnly, setFocusOnly] = useState(false)
  const selectedNode = nodes.find((node) => node.id === selected)

  const adjacency = useMemo(() => {
    const map = new Map<string, Set<string>>()
    nodes.forEach((node) => map.set(node.id, new Set()))
    edges.forEach(({ from, to }) => { map.get(from)?.add(to); map.get(to)?.add(from) })
    return map
  }, [nodes, edges])

  const connected = useMemo(() => {
    if (!selected) return new Set(nodes.map((node) => node.id))
    const result = new Set<string>([selected])
    adjacency.get(selected)?.forEach((id) => result.add(id))
    return result
  }, [selected, adjacency, nodes])

  const levels = useMemo(() => {
    const incoming = new Map(nodes.map((node) => [node.id, 0]))
    edges.forEach((edge) => incoming.set(edge.to, (incoming.get(edge.to) ?? 0) + 1))
    const result: AttackPathNode[][] = []
    let remaining = new Set(nodes.map((node) => node.id))
    let safety = nodes.length + 1
    while (remaining.size && safety--) {
      const level = nodes.filter((node) => remaining.has(node.id) && (incoming.get(node.id) ?? 0) === 0)
      if (!level.length) { result.push(nodes.filter((node) => remaining.has(node.id))); break }
      result.push(level)
      level.forEach((node) => remaining.delete(node.id))
      level.forEach((node) => edges.filter((edge) => edge.from === node.id).forEach((edge) => incoming.set(edge.to, Math.max(0, (incoming.get(edge.to) ?? 0) - 1))))
    }
    return result
  }, [nodes, edges])

  const selectNode = (node: AttackPathNode) => { setSelected(node.id); onSelect?.(node) }
  const resetView = () => { setSelected(nodes[0]?.id ?? null); setScale(1); setFocusOnly(false) }

  return (
    <div className="overflow-hidden rounded-2xl border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b px-5 py-4">
        <div>
          <div className="flex items-center gap-2 font-semibold"><Waypoints className="h-4 w-4 text-primary" /> Attack Path</div>
          <p className="mt-1 text-xs text-muted-foreground">Explore relationships from entry point to impacted resource.</p>
        </div>
        <div className="flex items-center gap-1 rounded-lg border bg-background/70 p-1">
          <button title="Zoom out" aria-label="Zoom out" onClick={() => setScale((v) => Math.max(.75, v - .1))} className="rounded-md p-1.5 hover:bg-muted"><Minus className="h-3.5 w-3.5" /></button>
          <span className="w-12 text-center text-[11px] font-medium">{Math.round(scale * 100)}%</span>
          <button title="Zoom in" aria-label="Zoom in" onClick={() => setScale((v) => Math.min(1.5, v + .1))} className="rounded-md p-1.5 hover:bg-muted"><Plus className="h-3.5 w-3.5" /></button>
          <button title="Focus selected" aria-label="Focus selected" onClick={() => setFocusOnly((v) => !v)} className={cn('rounded-md p-1.5 hover:bg-muted', focusOnly && 'bg-primary/10 text-primary')}><Maximize2 className="h-3.5 w-3.5" /></button>
          <button title="Reset view" aria-label="Reset view" onClick={resetView} className="rounded-md p-1.5 hover:bg-muted"><RotateCcw className="h-3.5 w-3.5" /></button>
        </div>
      </div>

      <div className="overflow-auto p-5">
        <div className="min-w-[760px] origin-left transition-transform duration-200" style={{ transform: `scale(${scale})` }}>
          <div className="flex items-center gap-3">
            {levels.map((level, levelIndex) => (
              <div key={levelIndex} className="flex min-w-[180px] flex-1 flex-col gap-3">
                {level.map((node) => {
                  const Icon = iconFor[node.type]
                  const active = selected === node.id
                  const visible = !focusOnly || connected.has(node.id)
                  return <button key={node.id} type="button" onClick={() => selectNode(node)} aria-pressed={active} className={cn('w-full rounded-xl border p-3 text-left transition-all duration-200 hover:-translate-y-0.5 hover:shadow-md', toneFor[node.type], active && 'ring-2 ring-primary/60 shadow-md', !visible && 'pointer-events-none opacity-20 saturate-0')}>
                    <div className="flex items-start gap-3">
                      <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border bg-background/70"><Icon className="h-4 w-4" /></span>
                      <span className="min-w-0 flex-1"><span className="block truncate text-sm font-semibold">{node.label}</span><span className="mt-0.5 block truncate text-[11px] text-muted-foreground">{node.meta ?? node.type}</span></span>
                      {node.severity && <span className="mt-0.5 inline-flex items-center gap-1 text-[10px] font-bold uppercase"><AlertTriangle className="h-3 w-3" />{node.severity}</span>}
                    </div>
                  </button>
                })}
                {levelIndex < levels.length - 1 && <div className="hidden" />}
              </div>
            ))}
          </div>
        </div>
      </div>

      {selectedNode && <div className="border-t bg-muted/20 px-5 py-4">
        <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">Selected node</div>
        <div className="mt-1 flex items-center justify-between gap-4"><div><div className="font-medium">{selectedNode.label}</div><div className="text-xs text-muted-foreground">{selectedNode.meta ?? selectedNode.type}</div></div><div className="text-xs text-muted-foreground">{edges.filter((edge) => edge.from === selectedNode.id || edge.to === selectedNode.id).length} relationships</div></div>
      </div>}
    </div>
  )
}
