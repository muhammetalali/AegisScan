import { CheckCircle2, CircleDashed, FileSearch, ShieldCheck, TrendingDown, TrendingUp } from 'lucide-react'
import type { DecisionAction } from './DecisionActionOrchestration'

type Props = { action: DecisionAction }

export function OutcomeIntelligencePanel({ action }: Props) {
  const verified = action.state === 'verified'
  const awaiting = action.state === 'awaiting_revalidation'
  const before = Number(action.riskBefore ?? 0)
  // Do not invent a post-remediation score: it must come from measured backend evidence.
  const afterValue = (action as DecisionAction & { riskAfter?: number }).riskAfter
  const after = verified && typeof afterValue === 'number' ? afterValue : null
  const delta = after === null ? null : Number((after - before).toFixed(1))
  const confidence = Number(action.confidenceBefore ?? 0)

  return <section className="overflow-hidden rounded-2xl border border-white/10 bg-slate-950/60">
    <header className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 px-5 py-4">
      <div><div className="text-[10px] font-bold uppercase tracking-[0.18em] text-cyan-300">Outcome intelligence</div><h3 className="mt-1 text-lg font-bold text-white">Prove the remediation outcome</h3><p className="mt-1 text-xs text-slate-400">Execution is not success until fresh evidence confirms the security impact.</p></div>
      <div className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-[10px] font-bold uppercase ${verified ? 'border-emerald-500/30 text-emerald-300' : awaiting ? 'border-amber-500/30 text-amber-300' : 'border-white/10 text-slate-400'}`}>{verified ? <CheckCircle2 size={13} /> : <CircleDashed size={13} />}{verified ? 'Verified outcome' : awaiting ? 'Awaiting proof' : 'Outcome pending'}</div>
    </header>
    <div className="grid gap-px bg-white/5 md:grid-cols-4">
      <Metric label="Risk baseline" value={before.toFixed(1)} hint="Before action" />
      <Metric label="Measured risk" value={after === null ? '—' : after.toFixed(1)} hint={after === null ? 'Fresh validation required' : 'After action'} />
      <Metric label="Risk delta" value={delta === null ? '—' : `${delta > 0 ? '+' : ''}${delta.toFixed(1)}`} hint={delta === null ? 'No fabricated outcome' : delta <= 0 ? 'Risk reduced' : 'Risk increased'} trend={delta === null ? undefined : delta <= 0 ? 'down' : 'up'} />
      <Metric label="Evidence confidence" value={`${confidence}%`} hint="Pre-action confidence" />
    </div>
    <div className="grid gap-4 p-5 lg:grid-cols-[1.2fr_.8fr]">
      <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4"><div className="flex items-center gap-2 text-xs font-semibold text-slate-200"><ShieldCheck size={15} /> Assurance chain</div><div className="mt-4 flex flex-wrap items-center gap-2 text-[10px] font-semibold">{['Decision', 'Action', 'Execution', 'Fresh evidence', 'Re-validation', 'Posture delta'].map((label, index) => <div key={label} className="flex items-center gap-2"><span className={`rounded-lg border px-2.5 py-2 ${index < 3 || (verified && index >= 3) ? 'border-cyan-400/20 bg-cyan-400/5 text-cyan-200' : 'border-white/10 text-slate-500'}`}>{label}</span>{index < 5 && <span className="text-slate-700">→</span>}</div>)}</div></div>
      <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4"><div className="flex items-center gap-2 text-xs font-semibold text-slate-200"><FileSearch size={15} /> Evidence gate</div><p className="mt-2 text-xs leading-5 text-slate-400">{verified ? 'The action reached its verification gate. A measured post-action score can now drive posture evolution.' : 'Do not mark risk as reduced until re-validation returns a measured outcome.'}</p>{verified && after === null && <div className="mt-3 rounded-lg border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-[10px] text-amber-200">Backend outcome telemetry is not yet exposed on this action.</div>}</div>
    </div>
  </section>
}

function Metric({ label, value, hint, trend }: { label: string; value: string; hint: string; trend?: 'up' | 'down' }) { return <div className="bg-slate-950/60 p-4"><div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div><div className="mt-2 flex items-center gap-2 text-2xl font-bold text-white">{value}{trend === 'down' ? <TrendingDown size={17} className="text-emerald-400" /> : trend === 'up' ? <TrendingUp size={17} className="text-red-400" /> : null}</div><div className="mt-1 text-[10px] text-slate-500">{hint}</div></div> }

export default OutcomeIntelligencePanel
