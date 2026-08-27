import { Activity, AlertTriangle, CircleCheck, FileSearch, GitBranch, Shield, Target, Waypoints } from 'lucide-react'

export type InvestigationContextRailProps = {
  risk: number
  confidence: number
  evidence: number
  verifiedEvidence: number
  findings: number
  critical: number
  affectedAssets: number
  relationships: number
  decisionState: string
  onFocus?: (section: string) => void
}

export function InvestigationContextRail({ risk, confidence, evidence, verifiedEvidence, findings, critical, affectedAssets, relationships, decisionState, onFocus }: InvestigationContextRailProps) {
  const items = [
    { id: 'risk', label: 'Risk posture', value: `${Math.round(risk)}`, suffix: '/100', icon: AlertTriangle },
    { id: 'confidence', label: 'Confidence', value: `${Math.round(confidence)}`, suffix: '%', icon: Activity },
    { id: 'evidence', label: 'Evidence', value: `${verifiedEvidence}/${evidence}`, suffix: ' verified', icon: FileSearch },
    { id: 'findings', label: 'Findings', value: `${critical}`, suffix: ` critical · ${findings} total`, icon: Shield },
    { id: 'blast', label: 'Affected assets', value: `${affectedAssets}`, suffix: '', icon: Target },
    { id: 'graph', label: 'Relationships', value: `${relationships}`, suffix: '', icon: Waypoints },
  ]

  return <aside className="rounded-2xl border bg-card/80 p-4 shadow-sm" aria-label="Investigation context"><div className="flex items-center justify-between gap-3"><div><p className="text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground">Investigation context</p><h2 className="mt-1 text-sm font-semibold">Live decision surface</h2></div><span className="inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[10px] font-semibold"><CircleCheck className="h-3 w-3" /> {decisionState}</span></div><div className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-6">{items.map(({ id, label, value, suffix, icon: Icon }) => <button key={id} type="button" onClick={() => onFocus?.(id)} className="rounded-xl border bg-background/60 p-3 text-left transition hover:-translate-y-0.5 hover:bg-muted/60 focus:outline-none focus:ring-2 focus:ring-primary/30"><div className="flex items-center gap-2 text-muted-foreground"><Icon className="h-3.5 w-3.5" /><span className="text-[10px] font-medium uppercase tracking-wide">{label}</span></div><div className="mt-1 text-lg font-bold tracking-tight">{value}<span className="ml-1 text-[10px] font-medium text-muted-foreground">{suffix}</span></div></button>)}</div></aside>
}
