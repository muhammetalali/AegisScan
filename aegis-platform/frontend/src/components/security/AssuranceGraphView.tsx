import { useMemo, useState } from 'react'
import { AlertTriangle, CircleDot, FileSearch, GitBranch, Link2, ShieldAlert, ShieldCheck, Target } from 'lucide-react'
import { useLanguageStore } from '@/stores/languageStore'
import { neighbors, type AssuranceGraph, type AssuranceNode, type AssuranceNodeType } from './AssuranceGraph'

const iconFor: Record<AssuranceNodeType, typeof Target> = {
  finding: ShieldAlert, asset: ShieldCheck, service: GitBranch, endpoint: CircleDot, evidence: FileSearch,
  validation: Target, control: ShieldCheck, threat: AlertTriangle, data: CircleDot, remediation: Target,
}
const typeLabel: Record<AssuranceNodeType, string> = {
  finding: 'Finding', asset: 'Asset', service: 'Engine or service', endpoint: 'Endpoint',
  evidence: 'Evidence', validation: 'Validation', control: 'Control', threat: 'Threat',
  data: 'Data', remediation: 'Remediation',
}
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** Replace opaque technical labels only in the display layer, never in saved evidence. */
export function readableGraphNodeLabel(node: AssuranceNode, ordinal: number, t: (text: string) => string): string {
  const label = node.label.trim()
  if (!label || uuidPattern.test(label)) return `${t(typeLabel[node.type])} #${ordinal + 1}`
  const scannerObservation = /^(nmap|nuclei|semgrep|checkov) (finding|evidence)$/i.exec(label)
  if (scannerObservation) {
    const kind = scannerObservation[2].toLowerCase() === 'finding' ? 'Finding' : 'Evidence'
    return `${t(kind)} · ${scannerObservation[1].toUpperCase()}`
  }
  return label
}

const CARD_WIDTH = 188
const COLUMN_STEP = 224
const ROW_STEP = 112
const LEFT_MARGIN = 30
const TOP_MARGIN = 42

export function AssuranceGraphView({ graph, onInvestigate }: { graph: AssuranceGraph; onInvestigate?: (node: AssuranceNode) => void }) {
  const t = useLanguageStore((state) => state.t)
  // Do not dim 7 out of 8 nodes when opening the graph for the first time.
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const selected = graph.nodes.find((node) => node.id === selectedId)
  const connected = useMemo(() => new Set([selectedId, ...(selectedId ? neighbors(graph, selectedId).map((n) => n.id) : [])]), [graph, selectedId])

  if (!graph.nodes.length) return <section className="rounded-2xl border bg-card p-8 text-center text-sm text-muted-foreground">{t('No assurance graph data available.')}</section>

  const columns: AssuranceNodeType[] = ['finding', 'threat', 'asset', 'service', 'endpoint', 'control', 'evidence', 'validation', 'remediation', 'data']
  const groups = columns.map((type) => graph.nodes.filter((node) => node.type === type)).filter((group) => group.length)
  const positions = new Map<string, { x: number; y: number }>()
  groups.forEach((group, gi) => group.forEach((node, ni) => positions.set(node.id, { x: LEFT_MARGIN + gi * COLUMN_STEP, y: TOP_MARGIN + ni * ROW_STEP })))
  const width = Math.max(850, LEFT_MARGIN * 2 + (groups.length - 1) * COLUMN_STEP + CARD_WIDTH)
  const height = Math.max(300, TOP_MARGIN * 2 + Math.max(...groups.map((group) => group.length)) * ROW_STEP)
  const labels = new Map(graph.nodes.map((node, index) => [node.id, readableGraphNodeLabel(node, index, t)]))
  const actionAvailable = Boolean(selected?.metadata?.validationId && onInvestigate)

  return <section className="overflow-hidden rounded-2xl border bg-card">
    <header className="flex flex-wrap items-start justify-between gap-3 border-b px-5 py-4">
      <div>
        <div className="flex items-center gap-2 text-sm font-semibold"><Link2 className="h-4 w-4 text-primary" />{t('Unified Assurance Graph')}</div>
        <p className="mt-1 text-sm text-muted-foreground">{t('Choose an item to highlight its related findings, engines and evidence.')}</p>
      </div>
      <div className="text-xs text-muted-foreground">{graph.nodes.length} {t('Nodes')} · {graph.edges.length} {t('Relations')}</div>
    </header>
    <div className="border-b bg-muted/10 px-5 py-2 text-xs text-muted-foreground">
      {t('Scroll horizontally to explore all relationships. Select an item to view its links.')}
    </div>
    <div className="overflow-x-auto p-4" role="region" aria-label={t('Security relationship diagram')} tabIndex={0}>
      <div className="relative" style={{ width, height }}>
        <svg className="pointer-events-none absolute inset-0 h-full w-full" viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
          <defs><marker id="assurance-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" /></marker></defs>
          {graph.edges.map((edge) => {
            const a = positions.get(edge.from)
            const b = positions.get(edge.to)
            if (!a || !b) return null
            const fromX = a.x + CARD_WIDTH
            const toX = b.x
            const fromY = a.y + 40
            const toY = b.y + 40
            const active = Boolean(selectedId && connected.has(edge.from) && connected.has(edge.to))
            return <path key={edge.id} d={`M ${fromX} ${fromY} C ${(fromX + toX) / 2} ${fromY}, ${(fromX + toX) / 2} ${toY}, ${toX} ${toY}`} fill="none" stroke="currentColor" markerEnd="url(#assurance-arrow)" strokeWidth={active ? 2.5 : 1.5} className={active ? 'text-primary' : 'text-muted-foreground/35'} />
          })}
        </svg>
        {graph.nodes.map((node, index) => {
          const p = positions.get(node.id)!
          const Icon = iconFor[node.type]
          const active = node.id === selectedId
          const related = connected.has(node.id)
          const label = labels.get(node.id)!
          return <button key={node.id} type="button" onClick={() => setSelectedId(active ? null : node.id)}
            style={{ left: p.x, top: p.y, width: CARD_WIDTH }}
            title={node.label}
            aria-pressed={active}
            aria-label={`${label} — ${t(typeLabel[node.type])}`}
            className={`absolute z-10 min-h-[82px] rounded-xl border bg-card px-3 py-2.5 text-start shadow-sm transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary ${active ? 'border-primary ring-2 ring-primary/60' : ''} ${selectedId && !related ? 'opacity-45' : 'opacity-100'}`}>
            <div className="flex items-center gap-2">
              <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border"><Icon className="h-4 w-4" /></span>
              <span className="min-w-0 text-sm font-semibold leading-5" dir="auto">{label}</span>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <span>{t(typeLabel[node.type])}</span>
              {node.confidence !== undefined && <span>{Math.round(node.confidence)}% {t('Confidence')}</span>}
            </div>
          </button>
        })}
      </div>
    </div>
    <footer className="flex flex-wrap items-center justify-between gap-3 border-t bg-muted/20 px-5 py-4">
      {selected ? <div className="min-w-0 flex-1">
        <div className="text-xs font-semibold">{t('Selected entity')}: {labels.get(selected.id)}</div>
        <details className="mt-1 text-xs text-muted-foreground">
          <summary className="cursor-pointer">{t('Technical details')}</summary>
          <code dir="ltr" className="mt-1 block break-all">{selected.label}</code>
          <code dir="ltr" className="mt-1 block break-all">{selected.id}</code>
        </details>
      </div> : <p className="text-sm text-muted-foreground">{t('All items are shown. Select one to focus on its connections.')}</p>}
      {selected && <button type="button" onClick={() => setSelectedId(null)} className="rounded-lg border px-3 py-2 text-xs font-semibold">{t('Show all')}</button>}
      {selected && actionAvailable && <button type="button" onClick={() => onInvestigate?.(selected)} className="inline-flex items-center gap-2 rounded-lg bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground"><Target className="h-4 w-4" />{t('Open investigation')}</button>}
    </footer>
  </section>
}
