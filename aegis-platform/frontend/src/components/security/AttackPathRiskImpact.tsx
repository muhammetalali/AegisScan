import { useMemo } from 'react'
import { Activity, Crosshair, Gauge, ShieldAlert, Target, TrendingUp } from 'lucide-react'
import type { AttackPathNode } from './AttackPathGraph'

export type RiskImpactModel = { riskScore: number; exploitability: number; impact: number; exposure: number; blastRadius: number; affectedAssets: number; affectedServices: number }

export function AttackPathRiskImpact({ nodes, model, onFocusRisk }: { nodes: AttackPathNode[]; model: RiskImpactModel; onFocusRisk?: () => void }) {
  const score = Math.max(0, Math.min(100, model.riskScore))
  const tier = score >= 85 ? 'Critical' : score >= 65 ? 'High' : score >= 40 ? 'Medium' : 'Low'
  const findingCount = nodes.filter((node) => node.type === 'finding').length
  const radius = useMemo(() => Math.max(1, model.blastRadius), [model.blastRadius])
  const metrics = [
    { label: 'Exploitability', value: model.exploitability, icon: <Crosshair className="h-3.5 w-3.5" /> },
    { label: 'Impact', value: model.impact, icon: <Target className="h-3.5 w-3.5" /> },
    { label: 'Exposure', value: model.exposure, icon: <Activity className="h-3.5 w-3.5" /> },
  ]

  return <section className="overflow-hidden rounded-2xl border bg-card">
    <header className="flex flex-wrap items-center justify-between gap-3 border-b px-5 py-4"><div><div className="flex items-center gap-2 font-semibold"><Gauge className="h-4 w-4 text-primary" /> Risk / Impact Analysis</div><p className="mt-1 text-xs text-muted-foreground">Quantify how exploitable exposure can propagate through the selected attack path.</p></div><button type="button" onClick={onFocusRisk} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><TrendingUp className="h-3.5 w-3.5" /> Focus risk</button></header>
    <div className="grid gap-5 p-5 lg:grid-cols-[230px_minmax(0,1fr)]">
      <div className="relative overflow-hidden rounded-2xl border bg-muted/10 p-5"><div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">Risk score</div><div className="mt-4 flex items-end gap-2"><span className="text-5xl font-black tracking-tight">{Math.round(score)}</span><span className="pb-1 text-sm text-muted-foreground">/ 100</span></div><div className="mt-3 h-2 overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full bg-primary transition-all duration-700" style={{ width: `${score}%` }} /></div><div className="mt-3 flex items-center justify-between text-[10px] text-muted-foreground"><span>0</span><span>50</span><span>100</span></div><div className="mt-5 inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase"><ShieldAlert className="h-3 w-3" /> {tier}</div></div>
      <div className="grid gap-4 md:grid-cols-3">{metrics.map((metric) => <Metric key={metric.label} label={metric.label} value={metric.value} icon={metric.icon} />)}<div className="rounded-xl border p-4 md:col-span-3"><div className="flex items-center justify-between"><div><div className="text-xs font-semibold">Impact matrix</div><p className="mt-1 text-[11px] text-muted-foreground">Exploitability × business impact</p></div><div className="text-[10px] text-muted-foreground">{findingCount} findings · {radius} blast-radius assets</div></div><div className="mt-4 grid grid-cols-5 gap-1.5" role="img" aria-label={`Risk matrix: exploitability ${model.exploitability}, impact ${model.impact}`}><div /><div className="text-center text-[9px] text-muted-foreground">Low</div><div className="text-center text-[9px] text-muted-foreground">Medium</div><div className="text-center text-[9px] text-muted-foreground">High</div><div className="text-center text-[9px] text-muted-foreground">Critical</div>{['Low','Medium','High','Critical'].map((impact, row) => <><div key={`label-${impact}`} className="flex items-center text-[9px] text-muted-foreground">{impact}</div>{['Low','Medium','High','Critical'].map((risk, col) => { const active = Math.round(model.impact / 25) >= row + 1 && Math.round(model.exploitability / 25) >= col + 1; return <div key={`${impact}-${risk}`} className={`relative h-9 rounded-md border ${active ? 'bg-primary/20 border-primary/30' : 'bg-muted/30'}`}>{active && row === Math.min(3, Math.floor(model.impact / 25)) && col === Math.min(3, Math.floor(model.exploitability / 25)) && <span className="absolute inset-0 m-auto h-2.5 w-2.5 rounded-full bg-primary shadow-[0_0_14px_hsl(var(--primary)/.8)]" />}</div> })}</> )}</div></div></div>
    </div>
    <div className="grid grid-cols-2 border-t md:grid-cols-4"><Stat label="Blast radius" value={`${radius} assets`} /><Stat label="Affected services" value={model.affectedServices} /><Stat label="Affected assets" value={model.affectedAssets} /><Stat label="Risk posture" value={tier} /></div>
  </section>
}

function Metric({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) { return <div className="rounded-xl border p-4"><div className="flex items-center gap-2 text-[11px] font-medium text-muted-foreground">{icon}{label}</div><div className="mt-2 text-2xl font-bold">{Math.round(value)}<span className="ml-1 text-xs font-medium text-muted-foreground">/100</span></div><div className="mt-2 h-1.5 rounded-full bg-muted"><div className="h-full rounded-full bg-primary" style={{ width: `${Math.max(0, Math.min(100, value))}%` }} /></div></div> }
function Stat({ label, value }: { label: string; value: string | number }) { return <div className="border-r px-5 py-3 last:border-r-0"><div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div><div className="mt-1 text-sm font-semibold">{value}</div></div> }
