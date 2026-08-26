import { useState } from 'react'
import { Activity, ChevronLeft, Crosshair, FileSearch, ShieldAlert, ShieldCheck, Waypoints } from 'lucide-react'
import { AttackPathGraph, type AttackPathEdge, type AttackPathNode } from './AttackPathGraph'
import { AttackPathNodeInspector } from './AttackPathNodeInspector'
import { EvidenceGraph, type EvidenceGraphEdge, type EvidenceGraphNode } from './EvidenceGraph'
import { EvidenceTimeline, type EvidenceEvent } from './EvidenceTimeline'

export type InvestigationWorkspaceProps = {
  title?: string
  subtitle?: string
  attackPath: { nodes: AttackPathNode[]; edges: AttackPathEdge[] }
  evidenceGraph: { nodes: EvidenceGraphNode[]; edges: EvidenceGraphEdge[] }
  evidenceEvents: EvidenceEvent[]
}

export function InvestigationWorkspace({ title = 'Security Investigation', subtitle = 'Trace the attack path, validate the finding, and inspect its evidence chain.', attackPath, evidenceGraph, evidenceEvents }: InvestigationWorkspaceProps) {
  const [selectedAttackNode, setSelectedAttackNode] = useState<AttackPathNode | null>(attackPath.nodes[0] ?? null)
  const [selectedEvidenceNode, setSelectedEvidenceNode] = useState<EvidenceGraphNode | null>(evidenceGraph.nodes[0] ?? null)
  const [activeView, setActiveView] = useState<'attack' | 'evidence'>('attack')

  const findings = attackPath.nodes.filter((node) => node.type === 'finding').length
  const critical = attackPath.nodes.filter((node) => node.severity === 'critical').length
  const verified = evidenceEvents.filter((event) => event.status === 'verified').length

  return <main className="min-h-full bg-background">
    <header className="sticky top-0 z-20 border-b bg-background/90 px-6 py-4 backdrop-blur">
      <div className="mx-auto max-w-[1600px]">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div><div className="flex items-center gap-2 text-xs text-muted-foreground"><span>Investigations</span><ChevronLeft className="h-3 w-3 rotate-180" /><span>Security</span></div><h1 className="mt-2 text-2xl font-bold tracking-tight">{title}</h1><p className="mt-1 max-w-2xl text-sm text-muted-foreground">{subtitle}</p></div>
          <div className="flex items-center gap-2 rounded-xl border bg-card px-3 py-2 text-xs"><Activity className="h-4 w-4 text-emerald-500" /><span className="font-medium">Investigation workspace</span><span className="text-muted-foreground">· UX mode</span></div>
        </div>
        <div className="mt-5 grid grid-cols-2 gap-2 md:grid-cols-4">
          <Metric icon={<Waypoints className="h-4 w-4" />} label="Attack nodes" value={attackPath.nodes.length} />
          <Metric icon={<ShieldAlert className="h-4 w-4" />} label="Critical findings" value={critical} />
          <Metric icon={<FileSearch className="h-4 w-4" />} label="Evidence events" value={evidenceEvents.length} />
          <Metric icon={<ShieldCheck className="h-4 w-4" />} label="Verified evidence" value={verified} />
        </div>
      </div>
    </header>

    <div className="mx-auto max-w-[1600px] space-y-5 p-6">
      <nav className="flex w-fit items-center gap-1 rounded-xl border bg-card p-1" aria-label="Investigation views">
        <ViewButton active={activeView === 'attack'} onClick={() => setActiveView('attack')} icon={<Crosshair className="h-3.5 w-3.5" />} label={`Attack Path${findings ? ` · ${findings} findings` : ''}`} />
        <ViewButton active={activeView === 'evidence'} onClick={() => setActiveView('evidence')} icon={<FileSearch className="h-3.5 w-3.5" />} label="Evidence Chain" />
      </nav>

      {activeView === 'attack' ? <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
        <AttackPathGraph nodes={attackPath.nodes} edges={attackPath.edges} onSelect={setSelectedAttackNode} />
        <AttackPathNodeInspector node={selectedAttackNode} nodes={attackPath.nodes} edges={attackPath.edges} onOpen={setSelectedAttackNode} />
      </section> : <section className="space-y-5">
        <EvidenceGraph nodes={evidenceGraph.nodes} edges={evidenceGraph.edges} onSelect={setSelectedEvidenceNode} />
        <EvidenceTimeline events={evidenceEvents} />
      </section>}

      <footer className="flex flex-wrap items-center justify-between gap-3 rounded-xl border bg-card px-4 py-3 text-xs text-muted-foreground"><span>UX-only investigation shell · backend integration intentionally deferred.</span><span>{attackPath.edges.length + evidenceGraph.edges.length} total relationships</span></footer>
    </div>
  </main>
}

function Metric({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) { return <div className="rounded-xl border bg-card p-3"><div className="flex items-center gap-2 text-muted-foreground">{icon}<span className="text-[11px] font-medium">{label}</span></div><div className="mt-1 text-xl font-bold tracking-tight">{value}</div></div> }
function ViewButton({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: React.ReactNode; label: string }) { return <button type="button" onClick={onClick} aria-pressed={active} className={`inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold transition ${active ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:bg-muted hover:text-foreground'}`}>{icon}{label}</button> }
