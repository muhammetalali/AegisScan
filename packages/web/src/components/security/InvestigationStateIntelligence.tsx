import type { ReactNode } from 'react'
import { Activity, CheckCircle2, CircleDot, GitCompareArrows, ShieldAlert, Sparkles } from 'lucide-react'

type InvestigationState = 'new' | 'investigating' | 'correlated' | 'confirmed' | 'decision-ready' | 'remediation' | 'validating' | 'resolved'

export interface InvestigationStateSignal {
  risk: number
  confidence: number
  sources: number
  conflicts: number
  critical: number
  hasValidation: boolean
  hasRemediation: boolean
  resolved: number
  regressed: number
}

const stages: Array<{ id: InvestigationState; label: string; description: string }> = [
  { id: 'new', label: 'New', description: 'Signal received' },
  { id: 'investigating', label: 'Investigating', description: 'Evidence under review' },
  { id: 'correlated', label: 'Correlated', description: 'Signals connected' },
  { id: 'confirmed', label: 'Confirmed', description: 'Confidence threshold reached' },
  { id: 'decision-ready', label: 'Decision Ready', description: 'Action can be evaluated' },
  { id: 'remediation', label: 'Remediation', description: 'Mitigation in progress' },
  { id: 'validating', label: 'Validating', description: 'Proof of fix pending' },
  { id: 'resolved', label: 'Resolved', description: 'Risk outcome verified' },
]

function deriveState(signal: InvestigationStateSignal): InvestigationState {
  if (signal.resolved > 0 && signal.regressed === 0 && signal.risk < 35) return 'resolved'
  if (signal.hasValidation && signal.hasRemediation) return 'validating'
  if (signal.hasRemediation) return 'remediation'
  if (signal.conflicts === 0 && signal.confidence >= 85 && signal.critical === 0) return 'decision-ready'
  if (signal.confidence >= 80 && signal.sources >= 3) return 'confirmed'
  if (signal.sources >= 2) return 'correlated'
  if (signal.sources > 0) return 'investigating'
  return 'new'
}

export function InvestigationStateIntelligence({ signal }: { signal: InvestigationStateSignal }) {
  const state = deriveState(signal)
  const activeIndex = stages.findIndex((stage) => stage.id === state)
  const readiness = Math.min(100, Math.round(signal.confidence * 0.55 + Math.min(signal.sources, 10) * 4 + (signal.conflicts === 0 ? 10 : 0)))
  const stateMeta = stages[activeIndex]

  return (
    <section className="rounded-2xl border bg-card/70 p-4 shadow-sm backdrop-blur-xl">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.18em] text-muted-foreground"><Activity className="h-3.5 w-3.5" /> Investigation State Intelligence</div>
          <div className="mt-2 flex items-center gap-2"><span className="rounded-full border px-2.5 py-1 text-xs font-bold">{stateMeta?.label ?? 'New'}</span><span className="text-xs text-muted-foreground">{stateMeta?.description}</span></div>
        </div>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Metric icon={<ShieldAlert className="h-3.5 w-3.5" />} label="Risk" value={`${Math.round(signal.risk)}`} />
          <Metric icon={<Sparkles className="h-3.5 w-3.5" />} label="Confidence" value={`${Math.round(signal.confidence)}%`} />
          <Metric icon={<GitCompareArrows className="h-3.5 w-3.5" />} label="Conflicts" value={`${signal.conflicts}`} />
          <Metric icon={<CheckCircle2 className="h-3.5 w-3.5" />} label="Readiness" value={`${readiness}%`} />
        </div>
      </div>
      <div className="mt-5 overflow-x-auto pb-1"><div className="flex min-w-[760px] items-start">{stages.map((stage, index) => { const active = index === activeIndex; const complete = index < activeIndex; return <div key={stage.id} className="flex min-w-[94px] flex-1 items-start"><div className="flex min-w-0 flex-1 flex-col items-center text-center"><div className={`grid h-7 w-7 place-items-center rounded-full border text-[10px] font-bold ${active ? 'ring-4 ring-primary/10' : ''}`}>{complete ? <CheckCircle2 className="h-4 w-4" /> : <CircleDot className="h-4 w-4" />}</div><div className={`mt-2 text-[10px] font-bold ${active ? 'text-foreground' : 'text-muted-foreground'}`}>{stage.label}</div><div className="mt-0.5 text-[9px] text-muted-foreground">{stage.description}</div></div>{index < stages.length - 1 && <div className={`mt-3 h-px flex-1 ${index < activeIndex ? 'bg-foreground/50' : 'bg-border'}`} />}</div> })}</div></div>
      <div className="mt-4 grid gap-2 text-xs sm:grid-cols-3">
        <Signal label="Evidence coverage" value={`${signal.sources} source${signal.sources === 1 ? '' : 's'}`} tone={signal.sources >= 3 ? 'good' : 'neutral'} />
        <Signal label="Validation" value={signal.hasValidation ? 'Evidence available' : 'Pending'} tone={signal.hasValidation ? 'good' : 'warn'} />
        <Signal label="Executive attention" value={signal.regressed || signal.critical ? `${signal.regressed + signal.critical} signal${signal.regressed + signal.critical === 1 ? '' : 's'}` : 'Stable'} tone={signal.regressed || signal.critical ? 'warn' : 'good'} />
      </div>
    </section>
  )
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: string }) { return <div className="rounded-xl border bg-background/60 px-3 py-2"><div className="flex items-center gap-1.5 text-[9px] font-semibold uppercase tracking-wider text-muted-foreground">{icon}{label}</div><div className="mt-1 text-sm font-bold">{value}</div></div> }
function Signal({ label, value, tone }: { label: string; value: string; tone: 'good' | 'warn' | 'neutral' }) { return <div className="rounded-xl border px-3 py-2"><div className="text-[9px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</div><div className={`mt-1 font-semibold ${tone === 'good' ? 'text-emerald-600 dark:text-emerald-400' : tone === 'warn' ? 'text-amber-600 dark:text-amber-400' : ''}`}>{value}</div></div> }
