import { Activity, ArrowDownRight, ArrowUpRight, CircleDot, ShieldCheck, Target, TrendingDown, TrendingUp } from 'lucide-react'

export type CisoTimelineMetric = {
  label: string
  current: number
  delta?: number
  suffix?: string
  inverse?: boolean
  baseline?: number
}

export type CisoTimelineEvent = {
  id: string
  title: string
  detail: string
  status: 'positive' | 'attention' | 'neutral'
  timestamp?: string
}

export type CisoExecutiveTimelineProps = {
  securityScore: number
  scoreDelta: number
  riskExposure: number
  remediationRate: number
  controlCoverage: number
  validationCoverage: number
  assuranceConfidence: number
  critical: number
  conflicts: number
  events?: CisoTimelineEvent[]
}

function Metric({ item }: { item: CisoTimelineMetric }) {
  const delta = item.delta
  const improved = delta === undefined ? false : item.inverse ? delta > 0 : delta < 0
  return <div className="rounded-xl border bg-background/50 p-3"><div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{item.label}</div><div className="mt-2 flex items-end justify-between gap-3">{item.baseline !== undefined ? <><div><div className="text-[9px] text-muted-foreground">Baseline</div><div className="text-xl font-black">{item.baseline}{item.suffix ?? ''}</div></div><div className="text-muted-foreground">→</div></> : <div><div className="text-[9px] text-muted-foreground">Current</div><div className="text-xl font-black">{item.current}{item.suffix ?? ''}</div></div>}<div className="text-right"><div className="text-[9px] text-muted-foreground">Current</div><div className="text-xl font-black">{item.current}{item.suffix ?? ''}</div></div></div>{delta === undefined ? <div className="mt-2 text-[10px] font-semibold text-muted-foreground">Baseline unavailable</div> : <div className={`mt-2 inline-flex items-center gap-1 text-[10px] font-bold ${improved ? 'text-emerald-600' : delta === 0 ? 'text-muted-foreground' : 'text-amber-600'}`}>{delta === 0 ? null : improved ? <ArrowUpRight className="h-3 w-3" /> : <ArrowDownRight className="h-3 w-3" />}{delta > 0 ? '+' : ''}{Number(delta.toFixed(1))}{item.suffix ?? ''}{!item.baseline && ' vs measured baseline'}</div>}</div>
}

export function CisoExecutiveTimeline(props: CisoExecutiveTimelineProps) {
  const events = props.events ?? [
    { id: 'posture', title: 'Security posture signal', detail: `Score ${props.securityScore.toFixed(1)} with ${props.scoreDelta >= 0 ? '+' : ''}${props.scoreDelta.toFixed(1)} delta.`, status: props.scoreDelta >= 0 ? 'positive' : 'attention' },
    { id: 'risk', title: 'Risk exposure snapshot', detail: `Current measured exposure is ${props.riskExposure.toFixed(1)}.`, status: props.riskExposure <= 35 ? 'positive' : props.riskExposure >= 70 ? 'attention' : 'neutral' },
    { id: 'assurance', title: 'Assurance confidence', detail: `${props.assuranceConfidence.toFixed(0)}% confidence across the current assurance signal.`, status: props.assuranceConfidence >= 80 ? 'positive' : 'attention' },
    { id: 'governance', title: 'Governance coverage', detail: `Controls ${props.controlCoverage.toFixed(0)}% · validation ${props.validationCoverage.toFixed(0)}% · remediation ${props.remediationRate.toFixed(0)}%.`, status: props.controlCoverage >= 80 && props.validationCoverage >= 80 ? 'positive' : 'attention' },
    { id: 'attention', title: 'Executive attention', detail: `${props.critical} critical signal${props.critical === 1 ? '' : 's'} · ${props.conflicts} conflict${props.conflicts === 1 ? '' : 's'} in the active model.`, status: props.critical > 0 || props.conflicts > 0 ? 'attention' : 'positive' },
  ]

  const metrics: CisoTimelineMetric[] = [
    { label: 'Security score', current: props.securityScore, delta: props.scoreDelta, inverse: true },
    { label: 'Risk exposure', current: props.riskExposure },
    { label: 'Control coverage', current: props.controlCoverage, suffix: '%', inverse: true },
    { label: 'Remediation rate', current: props.remediationRate, suffix: '%', inverse: true },
  ]

  return <section className="overflow-hidden rounded-2xl border bg-card shadow-sm" aria-label="CISO executive timeline">
    <header className="flex flex-wrap items-start justify-between gap-4 border-b px-5 py-4"><div><div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground"><Activity className="h-3.5 w-3.5" /> CISO Executive Timeline</div><h2 className="mt-1 text-xl font-black tracking-tight">Outcome evolution at executive altitude</h2><p className="mt-1 max-w-3xl text-xs text-muted-foreground">Current measured posture, risk, assurance and governance signals. Historical baselines appear only when explicitly supplied by the assurance source.</p></div><div className="rounded-full border px-3 py-1.5 text-[10px] font-bold">Measured signal view</div></header>
    <div className="grid gap-3 p-5 md:grid-cols-2 xl:grid-cols-4">{metrics.map((item) => <Metric key={item.label} item={item} />)}</div>
    <div className="border-t p-5"><div className="mb-4 flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-muted-foreground"><Target className="h-3.5 w-3.5" /> Executive signal timeline</div><div className="space-y-3">{events.map((event, index) => <div key={event.id} className="relative flex gap-3">{index < events.length - 1 && <div className="absolute left-[11px] top-6 h-[calc(100%+12px)] w-px bg-border" />}<div className={`relative z-10 mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-full border bg-card ${event.status === 'positive' ? 'text-emerald-600' : event.status === 'attention' ? 'text-amber-600' : 'text-muted-foreground'}`}>{event.status === 'positive' ? <ShieldCheck className="h-3.5 w-3.5" /> : event.status === 'attention' ? <TrendingUp className="h-3.5 w-3.5" /> : <CircleDot className="h-3.5 w-3.5" />}</div><div className="min-w-0 flex-1 rounded-xl border bg-background/40 p-3"><div className="flex flex-wrap items-center justify-between gap-2"><div className="text-xs font-bold">{event.title}</div>{event.timestamp && <span className="text-[9px] text-muted-foreground">{event.timestamp}</span>}</div><p className="mt-1 text-[10px] leading-4 text-muted-foreground">{event.detail}</p></div></div>)}</div></div>
  </section>
}

export default CisoExecutiveTimeline
