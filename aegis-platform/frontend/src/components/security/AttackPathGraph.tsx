import { useMemo, useState } from 'react'
import { AlertTriangle, Database, Globe2, Server, ShieldAlert, Waypoints } from 'lucide-react'
import { cn } from '@/utils/cn'

export type AttackPathNode = {
  id: string
  label: string
  type: 'entry' | 'asset' | 'service' | 'finding' | 'data'
  severity?: 'critical' | 'high' | 'medium' | 'low'
  meta?: string
}

export type AttackPathEdge = {
  from: string
  to: string
  label?: string
}

const iconFor = {
  entry: Globe2,
  asset: Server,
  service: Waypoints,
  finding: ShieldAlert,
  data: Database,
}

const toneFor = {
  entry: 'border-sky-500/40 bg-sky-500/10',
  asset: 'border-violet-500/40 bg-violet-500/10',
  service: 'border-cyan-500/40 bg-cyan-500/10',
  finding: 'border-red-500/50 bg-red-500/10',
  data: 'border-amber-500/40 bg-amber-500/10',
}

export function AttackPathGraph({ nodes, edges, onSelect }: { nodes: AttackPathNode[]; edges: AttackPathEdge[]; onSelect?: (node: AttackPathNode) => void }) {
  const [selected, setSelected] = useState<string | null>(nodes[0]?.id ?? null)
  const selectedNode = nodes.find((node) => node.id === selected)

  const levels = useMemo(() => {
    const incoming = new Map(nodes.map((node) => [node.id, 0]))
    edges.forEach((edge) => incoming.set(edge.to, (incoming.get(edge.to) ?? 0) + 1))
    const result: AttackPathNode[][] = []
    let remaining = new Set(nodes.map((node) => node.id))
    let safety = nodes.length + 1
    while (remaining.size && safety--) {
      const level = nodes.filter((node) => remaining.has(node.id) && (incoming.get(node.id) ?? 0) === 0)
      if (!level.length) {
        result.push(nodes.filter((node) => remaining.has(node.id)))
        break
      }
      result.push(level)
      level.forEach((node) => remaining.delete(node.id))
      level.forEach((node) => edges.filter((edge) => edge.from === node.id).forEach((edge) => incoming.set(edge.to, Math.max(0, (incoming.get(edge.to) ?? 0) - 1))))
    }
    return result
  }, [nodes, edges])

  const selectNode = (node: AttackPathNode) => {
    setSelected(node.id)
    onSelect?.(node)
  }

  return (
    <div className="rounded-2xl border bg-card overflow-hidden">
      <div className="flex items-center justify-between border-b px-5 py-4">
        <div>
          <div className="flex items-center gap-2 font-semibold"><Waypoints className="h-4 w-4 text-primary" /> Attack Path</div>
          <p className="mt-1 text-xs text-muted-foreground">Interactive relationship map from entry point to impacted resource.</p>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground"><span className="h-2 w-2 rounded-full bg-emerald-500" /> validated path</div>
      </div>

      <div className="overflow-x-auto p-5">
        <div className="flex min-w-[760px] items-center gap-3">
          {levels.map((level, levelIndex) => (
            <div key={levelIndex} className="flex min-w-[160px] flex-1 flex-col gap-3">
              {level.map((node) => {
                const Icon = iconFor[node.type]
                const active = selected === node.id
                return (
                  <button key={node.id} type="button" onClick={() => selectNode(node)} className={cn('group w-full rounded-xl border p-3 text-left transition-all hover:-translate-y-0.5 hover:shadow-md', toneFor[node.type], active && 'ring-2 ring-primary/60 shadow-md')}>
                    <div className="flex items-start gap-3">
                      <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border bg-background/70"><Icon className="h-4 w-4" /></span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm font-semibold">{node.label}</span>
                        <span className="mt-0.5 block truncate text-[11px] text-muted-foreground">{node.meta ?? node.type}</span>
                      </span>
                      {node.severity && <span className="mt-0.5 inline-flex items-center gap-1 text-[10px] font-bold uppercase"><AlertTriangle className="h-3 w-3" />{node.severity}</span>}
                    </div>
                  </button>
                )
              })}
              {levelIndex < levels.length - 1 && <div className="hidden" />}
            </div>
          ))}
        </div>
      </div>

      {selectedNode && (
        <div className="border-t bg-muted/20 px-5 py-4">
          <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">Selected node</div>
          <div className="mt-1 flex items-center justify-between gap-4">
            <div><div className="font-medium">{selectedNode.label}</div><div className="text-xs text-muted-foreground">{selectedNode.meta ?? selectedNode.type}</div></div>
            <div className="text-xs text-muted-foreground">{edges.filter((edge) => edge.from === selectedNode.id || edge.to === selectedNode.id).length} relationships</div>
          </div>
        </div>
      )}
    </div>
  )
}
