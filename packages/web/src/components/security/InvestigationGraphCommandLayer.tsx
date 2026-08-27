import { useMemo, useState } from 'react'
import { Crosshair, Filter, GitBranch, Layers3, ShieldAlert } from 'lucide-react'
import { AssuranceGraphView } from './AssuranceGraphView'
import type { AssuranceGraph, AssuranceNode } from './AssuranceGraph'

type FilterType = AssuranceNode['type'] | 'all'

const filters: { key: FilterType; label: string }[] = [
  { key: 'all', label: 'All' }, { key: 'finding', label: 'Findings' }, { key: 'evidence', label: 'Evidence' },
  { key: 'control', label: 'Controls' }, { key: 'validation', label: 'Validation' }, { key: 'remediation', label: 'Remediation' },
  { key: 'asset', label: 'Assets' }, { key: 'threat', label: 'Threats' },
]

export function InvestigationGraphCommandLayer({ graph, onInvestigate }: { graph: AssuranceGraph; onInvestigate?: (node: AssuranceNode) => void }) {
  const [filter, setFilter] = useState<FilterType>('all')
  const [focus, setFocus] = useState<'all' | 'critical' | 'conflicted'>('all')
  const filtered = useMemo(() => {
    const nodes = graph.nodes.filter((node) => (filter === 'all' || node.type === filter) && (focus === 'all' || (focus === 'critical' ? node.severity === 'critical' : Boolean(node.conflictCount))))
    const ids = new Set(nodes.map((node) => node.id))
    return { nodes, edges: graph.edges.filter((edge) => ids.has(edge.from) && ids.has(edge.to)) }
  }, [graph, filter, focus])

  const counts = useMemo(() => ({ critical: graph.nodes.filter((node) => node.severity === 'critical').length, conflicts: graph.nodes.reduce((sum, node) => sum + (node.conflictCount ?? 0), 0) }), [graph])

  return <section className="space-y-3 rounded-2xl border bg-card p-4 shadow-sm">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div><div className="flex items-center gap-2 text-sm font-bold"><Crosshair className="h-4 w-4 text-primary" /> Investigation Graph Command Layer</div><p className="mt-1 text-xs text-muted-foreground">Filter the same assurance graph before opening an investigation. No parallel data model.</p></div>
      <div className="flex items-center gap-2 text-[10px] text-muted-foreground"><span className="inline-flex items-center gap-1 rounded-full border px-2 py-1"><Layers3 className="h-3 w-3" /> {filtered.nodes.length} visible</span><span className="inline-flex items-center gap-1 rounded-full border px-2 py-1"><GitBranch className="h-3 w-3" /> {filtered.edges.length} links</span></div>
    </div>
    <div className="flex flex-wrap gap-1.5" role="toolbar" aria-label="Graph filters">{filters.map((item) => <button key={item.key} type="button" onClick={() => setFilter(item.key)} className={`rounded-lg border px-2.5 py-1.5 text-[10px] font-semibold transition ${filter === item.key ? 'border-primary/40 bg-primary/10 text-primary' : 'hover:bg-muted'}`}>{item.label}</button>)}<span className="mx-1 hidden w-px bg-border sm:block" /><button type="button" onClick={() => setFocus(focus === 'critical' ? 'all' : 'critical')} className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1.5 text-[10px] font-semibold ${focus === 'critical' ? 'border-red-500/30 bg-red-500/10 text-red-600' : ''}`}><ShieldAlert className="h-3 w-3" /> Critical {counts.critical}</button><button type="button" onClick={() => setFocus(focus === 'conflicted' ? 'all' : 'conflicted')} className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1.5 text-[10px] font-semibold ${focus === 'conflicted' ? 'border-amber-500/30 bg-amber-500/10 text-amber-600' : ''}`}><Filter className="h-3 w-3" /> Conflicts {counts.conflicts}</button></div>
    {filtered.nodes.length ? <AssuranceGraphView graph={filtered} onInvestigate={onInvestigate} /> : <div className="rounded-xl border border-dashed p-8 text-center text-xs text-muted-foreground">No nodes match the current investigation filters.</div>}
  </section>
}

export default InvestigationGraphCommandLayer
