import { ArrowDownRight, ArrowUpRight, CheckCircle2, CircleDashed, Gauge, ShieldCheck, Sparkles } from 'lucide-react'
import type { DecisionAction } from './DecisionActionOrchestration'

type OutcomePostureBridgeProps = {
  action: DecisionAction
  currentPosture?: number
  previousPosture?: number
}

/**
 * Visual bridge between remediation outcomes and posture evolution.
 * It deliberately refuses to infer an after-risk/posture value when the
 * backend has not measured one yet.
 */
export function OutcomePostureBridge({ action, currentPosture, previousPosture }: OutcomePostureBridgeProps) {
  const verified = action.state === 'verified'
  const beforeRisk = Number(action.riskBefore ?? 0)
  const afterRisk = typeof (action as DecisionAction & { riskAfter?: unknown }).riskAfter === 'number'
    ? Number((action as DecisionAction & { riskAfter: number }).riskAfter)
    : null
  const riskDelta = afterRisk === null ? null : Number((afterRisk - beforeRisk).toFixed(1))
  const postureDelta = currentPosture != null && previousPosture != null
    ? Number((currentPosture - previousPosture).toFixed(1))
    : null

  const outcomeState = verified && afterRisk !== null ? 'measured' : verified ? 'awaiting_posture' : 'pending'

  return (
    <section className="overflow-hidden rounded-2xl border border-white/10 bg-slate-950/60">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 px-5 py-4">
        <div>
          <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.2em] text-cyan-300">
            <Sparkles size={13} /> Outcome → Posture
          </div>
          <h3 className="mt-1 text-lg font-bold text-white">Security posture evolution</h3>
          <p className="mt-1 text-xs text-slate-400">Only measured outcomes are allowed to move the assurance posture.</p>
        </div>
        <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider ${outcomeState === 'measured' ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-300' : outcomeState === 'awaiting_posture' ? 'border-amber-500/30 bg-amber-500/5 text-amber-300' : 'border-white/10 text-slate-400'}`}>
          {outcomeState === 'measured' ? <CheckCircle2 size={13} /> : <CircleDashed size={13} />}
          {outcomeState === 'measured' ? 'Measured' : outcomeState === 'awaiting_posture' ? 'Awaiting posture signal' : 'Pending verification'}
        </span>
      </div>

      <div className="grid gap-px bg-white/5 md:grid-cols-3">
        <Metric label="Risk before" value={beforeRisk.toFixed(1)} hint="Decision baseline" />
        <Metric label="Risk after" value={afterRisk === null ? '—' : afterRisk.toFixed(1)} hint={afterRisk === null ? 'Fresh measured outcome required' : 'Post-remediation measurement'} trend={riskDelta == null ? undefined : riskDelta <= 0 ? 'down' : 'up'} />
        <Metric label="Posture delta" value={postureDelta == null ? '—' : `${postureDelta > 0 ? '+' : ''}${postureDelta.toFixed(1)}`} hint={postureDelta == null ? 'Waiting for posture telemetry' : 'Current vs previous posture'} trend={postureDelta == null ? undefined : postureDelta >= 0 ? 'up' : 'down'} />
      </div>

      <div className="grid gap-4 p-5 lg:grid-cols-[1.4fr_.6fr]">
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200"><ShieldCheck size={15} /> Assurance propagation</div>
          <div className="mt-4 grid gap-2 sm:grid-cols-5">
            {[
              ['Action', action.state !== 'pending'],
              ['Evidence', verified],
              ['Risk', afterRisk !== null],
              ['Posture', postureDelta !== null],
              ['Executive', postureDelta !== null],
            ].map(([label, complete]) => (
              <div key={String(label)} className={`rounded-xl border p-3 ${complete ? 'border-cyan-400/20 bg-cyan-400/5' : 'border-white/10 bg-black/10'}`}>
                <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
                <div className={`mt-2 text-xs font-semibold ${complete ? 'text-cyan-200' : 'text-slate-600'}`}>{complete ? 'Signal ready' : 'Awaiting'}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200"><Gauge size={15} /> Posture guardrail</div>
          <div className="mt-3 text-xs leading-5 text-slate-400">
            {postureDelta === null
              ? 'No posture movement is claimed until measured outcome telemetry is available.'
              : `Posture changed from ${previousPosture?.toFixed(1)} to ${currentPosture?.toFixed(1)}. The delta can now flow to executive impact.`}
          </div>
        </div>
      </div>
    </section>
  )
}

function Metric({ label, value, hint, trend }: { label: string; value: string; hint: string; trend?: 'up' | 'down' }) {
  return <div className="bg-slate-950/60 p-4">
    <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
    <div className="mt-2 flex items-center gap-2 text-2xl font-bold text-white">{value}{trend === 'down' ? <ArrowDownRight size={17} className="text-emerald-400" /> : trend === 'up' ? <ArrowUpRight size={17} className="text-amber-400" /> : null}</div>
    <div className="mt-1 text-[10px] text-slate-500">{hint}</div>
  </div>
}

export default OutcomePostureBridge
