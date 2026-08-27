import { ArrowUpRight, CheckCircle2, CircleAlert, ShieldCheck, TrendingDown, TrendingUp } from 'lucide-react'

export interface CisoImpactSignal {
  postureDelta: number
  riskDelta: number
  resolved: number
  regressed: number
  critical: number
  confidence: number
  sources: number
}

interface CisoImpactBridgeProps {
  signal: CisoImpactSignal
  onOpenExecutive?: () => void
}

export function CisoImpactBridge({ signal, onOpenExecutive }: CisoImpactBridgeProps) {
  const improving = signal.riskDelta < 0
  const postureImproving = signal.postureDelta > 0

  return (
    <section className="aegis-surface aegis-surface-grid overflow-hidden rounded-2xl border border-white/10">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-white/10 p-5">
        <div>
          <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.2em] text-cyan-300">
            <ShieldCheck size={14} /> CISO Impact Bridge
          </div>
          <h2 className="mt-2 text-lg font-semibold text-white">Operational outcomes → executive impact</h2>
          <p className="mt-1 max-w-2xl text-xs text-slate-400">Only measured assurance deltas are promoted into the executive narrative.</p>
        </div>
        {onOpenExecutive && <button type="button" onClick={onOpenExecutive} className="aegis-command-surface inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold text-slate-200 hover:text-white">Open executive view <ArrowUpRight size={14} /></button>}
      </header>

      <div className="grid gap-px bg-white/5 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label="Posture delta" value={signal.postureDelta === 0 ? '—' : `${signal.postureDelta > 0 ? '+' : ''}${signal.postureDelta.toFixed(1)}`} good={postureImproving} icon={postureImproving ? <TrendingUp size={14} /> : <TrendingDown size={14} />} />
        <Metric label="Risk delta" value={signal.riskDelta === 0 ? '—' : `${signal.riskDelta > 0 ? '+' : ''}${signal.riskDelta.toFixed(1)}`} good={improving} icon={improving ? <TrendingDown size={14} /> : <TrendingUp size={14} />} />
        <Metric label="Resolved / regressed" value={`${signal.resolved} / ${signal.regressed}`} good={signal.resolved > signal.regressed} icon={signal.resolved >= signal.regressed ? <CheckCircle2 size={14} /> : <CircleAlert size={14} />} />
        <Metric label="Decision confidence" value={`${signal.confidence}%`} good={signal.confidence >= 80} icon={<ShieldCheck size={14} />} />
      </div>

      <div className="grid gap-3 p-5 md:grid-cols-[1fr_auto] md:items-center">
        <div className="rounded-xl border border-white/10 bg-black/10 p-4">
          <div className="text-[9px] font-bold uppercase tracking-[0.16em] text-slate-500">Executive narrative</div>
          <p className="mt-2 text-sm leading-6 text-slate-300">
            {signal.regressed > 0
              ? `${signal.regressed} assurance regression${signal.regressed === 1 ? '' : 's'} require executive attention. ${signal.critical} critical exposure${signal.critical === 1 ? '' : 's'} remain in the measured signal set.`
              : signal.resolved > 0 && improving
                ? `${signal.resolved} issue${signal.resolved === 1 ? '' : 's'} moved toward resolution and measured risk decreased. Posture impact is ${postureImproving ? 'positive' : 'not yet measurable'}.`
                : 'No measured outcome is strong enough to claim executive improvement yet; continue validation and evidence collection.'}
          </p>
        </div>
        <div className="rounded-xl border border-white/10 bg-white/[0.02] px-4 py-3 text-xs text-slate-400">
          <div className="font-semibold text-slate-200">Evidence basis</div>
          <div className="mt-1">{signal.sources} sources · {signal.confidence}% confidence</div>
        </div>
      </div>
    </section>
  )
}

function Metric({ label, value, good, icon }: { label: string; value: string; good: boolean; icon: React.ReactNode }) {
  return <div className="bg-slate-950/50 p-4"><div className="text-[9px] font-bold uppercase tracking-wider text-slate-500">{label}</div><div className={`mt-2 flex items-center gap-2 text-xl font-bold ${good ? 'text-emerald-300' : 'text-slate-100'}`}>{icon}{value}</div></div>
}

export default CisoImpactBridge
