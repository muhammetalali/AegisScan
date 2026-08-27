import { AlertTriangle, ArrowDownRight, ArrowUpRight, ShieldCheck, Target } from 'lucide-react'

export interface DecisionIntelligencePanelProps {
  risk: number
  confidence: number
  conflicts: number
  priority: number
  executiveImpact: number
  urgency: string
}

const clamp = (value: number) => Math.max(0, Math.min(100, value))

function Metric({ label, value, hint }: { label: string; value: number; hint: string }) {
  const normalized = clamp(value)
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.025] p-3">
      <div className="flex items-center justify-between text-[10px] font-semibold uppercase tracking-wider text-slate-500">
        <span>{label}</span><span className="text-slate-300">{value}</span>
      </div>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/10">
        <div className="h-full rounded-full bg-primary transition-all duration-500" style={{ width: `${normalized}%` }} />
      </div>
      <div className="mt-2 text-[10px] text-slate-500">{hint}</div>
    </div>
  )
}

export function DecisionIntelligencePanel({ risk, confidence, conflicts, priority, executiveImpact, urgency }: DecisionIntelligencePanelProps) {
  const conflictPressure = clamp(conflicts * 20)
  const riskDirection = risk >= 70 ? <ArrowUpRight size={13} /> : <ArrowDownRight size={13} />

  return (
    <div className="rounded-2xl border border-white/10 bg-slate-950/30 p-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.18em] text-cyan-300"><ShieldCheck size={14} /> Decision intelligence</div>
          <p className="mt-1 text-xs text-slate-500">A compact risk-to-action view derived from the decision signal.</p>
        </div>
        <span className="rounded-full border border-white/10 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">{urgency}</span>
      </div>

      <div className="mt-4 grid gap-2 sm:grid-cols-2">
        <Metric label="Risk" value={risk} hint={risk >= 70 ? 'Elevated exposure' : 'Within monitored range'} />
        <Metric label="Confidence" value={confidence} hint={confidence >= 80 ? 'Strong signal agreement' : 'Review supporting evidence'} />
        <Metric label="Executive impact" value={executiveImpact} hint="Potential business-level consequence" />
        <Metric label="Decision priority" value={priority} hint="Operational ordering signal" />
      </div>

      <div className="mt-3 grid gap-2 sm:grid-cols-2">
        <div className="flex items-center gap-3 rounded-xl border border-amber-500/15 bg-amber-500/5 p-3">
          <AlertTriangle size={16} className="text-amber-300" />
          <div className="flex-1"><div className="text-[10px] uppercase tracking-wider text-slate-500">Conflict pressure</div><div className="mt-1 text-sm font-semibold text-slate-200">{conflicts} source conflict{conflicts === 1 ? '' : 's'}</div></div>
          <div className="h-8 w-1 overflow-hidden rounded-full bg-white/10"><div className="w-full rounded-full bg-amber-400" style={{ height: `${conflictPressure}%` }} /></div>
        </div>
        <div className="flex items-center gap-3 rounded-xl border border-cyan-500/15 bg-cyan-500/5 p-3">
          <Target size={16} className="text-cyan-300" />
          <div><div className="text-[10px] uppercase tracking-wider text-slate-500">Risk posture</div><div className="mt-1 flex items-center gap-1 text-sm font-semibold text-slate-200">{riskDirection}{risk >= 70 ? 'Escalate' : 'Monitor'}</div></div>
        </div>
      </div>
    </div>
  )
}

export default DecisionIntelligencePanel
