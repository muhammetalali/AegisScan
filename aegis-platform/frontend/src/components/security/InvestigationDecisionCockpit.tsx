import { AlertTriangle, ArrowRight, CheckCircle2, Gauge, ShieldAlert, Target } from 'lucide-react'
import type { DecisionState } from './UnifiedSecurityDecisionLayer'

export type InvestigationDecisionCockpitProps = {
  risk: number
  confidence: number
  evidenceCount: number
  verifiedEvidence: number
  conflicts: number
  affectedAssets: number
  decisionState: DecisionState
  onInvestigate?: () => void
  onDecide?: () => void
}

export function InvestigationDecisionCockpit({ risk, confidence, evidenceCount, verifiedEvidence, conflicts, affectedAssets, decisionState, onInvestigate, onDecide }: InvestigationDecisionCockpitProps) {
  const evidenceSufficiency = evidenceCount === 0 ? 0 : Math.round((verifiedEvidence / evidenceCount) * 100)
  const confidenceGate = confidence >= 75
  const conflictGate = conflicts === 0
  const evidenceGate = evidenceSufficiency >= 60
  const decisionReady = decisionState === 'ready' || (risk >= 70 && confidenceGate && evidenceGate && conflictGate)
  const readiness = Math.round((Number(confidenceGate) + Number(evidenceGate) + Number(conflictGate) + Number(risk >= 70)) * 25)

  const decisionLabel = decisionReady ? 'Decision ready' : conflicts > 0 ? 'Conflict review required' : 'Investigation in progress'

  return (
    <section className="rounded-2xl border bg-card p-4 shadow-sm" aria-label="Investigation decision cockpit">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            <Gauge className="h-4 w-4" /> Decision cockpit
          </div>
          <h2 className="mt-1 text-lg font-bold tracking-tight">Evidence-backed decision readiness</h2>
          <p className="mt-1 text-xs text-muted-foreground">A decision gate derived from the active investigation context.</p>
        </div>
        <div className={`rounded-full border px-3 py-1.5 text-xs font-bold ${decisionReady ? 'text-emerald-600' : 'text-amber-600'}`}>
          {decisionLabel}
        </div>
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Signal icon={<ShieldAlert className="h-4 w-4" />} label="Risk" value={`${Math.round(risk)}`} hint={risk >= 70 ? 'High impact' : 'Moderate impact'} />
        <Signal icon={<Gauge className="h-4 w-4" />} label="Confidence" value={`${Math.round(confidence)}%`} hint={confidenceGate ? 'Gate passed' : 'Needs evidence'} />
        <Signal icon={<CheckCircle2 className="h-4 w-4" />} label="Evidence sufficiency" value={`${evidenceSufficiency}%`} hint={`${verifiedEvidence}/${evidenceCount} verified`} />
        <Signal icon={<Target className="h-4 w-4" />} label="Blast radius" value={`${affectedAssets}`} hint="Affected assets" />
      </div>

      <div className="mt-4 rounded-xl border bg-background/60 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
          <span className="font-semibold">Decision gate</span>
          <span className="text-muted-foreground">Readiness {readiness}%</span>
        </div>
        <div className="mt-2 h-2 overflow-hidden rounded-full bg-muted">
          <div className="h-full rounded-full bg-primary transition-all" style={{ width: `${readiness}%` }} />
        </div>
        <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
          <Gate ok={confidenceGate} label="Confidence" />
          <Gate ok={evidenceGate} label="Evidence" />
          <Gate ok={conflictGate} label="No unresolved conflicts" />
          <Gate ok={risk >= 70} label="Material risk" />
        </div>
      </div>

      {conflicts > 0 && (
        <div className="mt-3 flex items-center gap-2 rounded-xl border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          {conflicts} conflict signal{conflicts === 1 ? '' : 's'} remain in the active context. Resolve them before treating the recommendation as high-confidence.
        </div>
      )}

      <div className="mt-4 flex flex-wrap justify-end gap-2">
        <button type="button" onClick={onInvestigate} className="rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted">Investigate blockers</button>
        <button type="button" disabled={!decisionReady} onClick={onDecide} className="inline-flex items-center gap-2 rounded-lg bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground disabled:cursor-not-allowed disabled:opacity-40">Continue to decision <ArrowRight className="h-3.5 w-3.5" /></button>
      </div>
    </section>
  )
}

function Signal({ icon, label, value, hint }: { icon: React.ReactNode; label: string; value: string; hint: string }) {
  return <div className="rounded-xl border p-3"><div className="flex items-center gap-2 text-muted-foreground">{icon}<span className="text-[11px] font-medium">{label}</span></div><div className="mt-1 text-xl font-bold tracking-tight">{value}</div><div className="mt-1 text-[10px] text-muted-foreground">{hint}</div></div>
}

function Gate({ ok, label }: { ok: boolean; label: string }) {
  return <span className={`rounded-full border px-2 py-1 font-medium ${ok ? 'text-emerald-600' : 'text-amber-600'}`}>{ok ? '✓' : '!' } {label}</span>
}
