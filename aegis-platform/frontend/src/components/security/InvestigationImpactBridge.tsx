import { ArrowDownRight, ArrowUpRight, BriefcaseBusiness, GitBranch, ShieldCheck, Target } from 'lucide-react'

export type InvestigationImpactBridgeProps = {
  risk: number
  blastRadius: number
  affectedAssets: number
  evidenceCount: number
  verifiedEvidence: number
  confidence: number
  conflicts: number
  decisionState: string
  executiveOutcomeScore?: number
}

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)))

export function InvestigationImpactBridge({
  risk,
  blastRadius,
  affectedAssets,
  evidenceCount,
  verifiedEvidence,
  confidence,
  conflicts,
  decisionState,
  executiveOutcomeScore,
}: InvestigationImpactBridgeProps) {
  const assurance = evidenceCount ? clamp((verifiedEvidence / evidenceCount) * 100) : 0
  const outcome = executiveOutcomeScore ?? clamp(confidence * 0.45 + assurance * 0.35 + Math.max(0, 100 - conflicts * 10) * 0.2)
  const attention = risk >= 85 || conflicts >= 3 ? 'Critical attention' : risk >= 65 || conflicts > 0 ? 'Elevated attention' : 'Normal attention'
  const radiusPressure = clamp(blastRadius * 8)

  return (
    <section className="overflow-hidden rounded-2xl border bg-card" aria-label="Investigation impact bridge">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b px-5 py-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            <GitBranch className="h-4 w-4" /> Decision → Posture → CISO bridge
          </div>
          <h2 className="mt-1 text-lg font-bold tracking-tight">One investigation, one executive signal</h2>
          <p className="mt-1 text-xs text-muted-foreground">Blast radius, assurance, decision state, and executive outcome remain derived from the same investigation context.</p>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-bold">
          <BriefcaseBusiness className="h-3.5 w-3.5" /> {attention}
        </span>
      </header>

      <div className="grid gap-4 p-5 lg:grid-cols-[1.2fr_1fr_1fr]">
        <div className="rounded-xl border bg-muted/10 p-4">
          <div className="flex items-center gap-2 text-xs font-semibold"><Target className="h-4 w-4" /> Blast radius</div>
          <div className="mt-3 flex items-end gap-3"><span className="text-4xl font-black">{blastRadius}</span><span className="pb-1 text-xs text-muted-foreground">reachable nodes</span></div>
          <div className="mt-3 grid grid-cols-2 gap-2 text-xs"><div className="rounded-lg border p-2"><div className="text-[10px] text-muted-foreground">Affected assets</div><div className="mt-1 font-bold">{affectedAssets}</div></div><div className="rounded-lg border p-2"><div className="text-[10px] text-muted-foreground">Pressure</div><div className="mt-1 font-bold">{radiusPressure}/100</div></div></div>
        </div>

        <div className="rounded-xl border p-4">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Assurance</div>
          <div className="mt-2 flex items-center justify-between"><span className="text-3xl font-black">{assurance}%</span><ShieldCheck className="h-5 w-5 text-emerald-600" /></div>
          <div className="mt-3 h-2 overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full bg-primary" style={{ width: `${assurance}%` }} /></div>
          <div className="mt-2 text-[10px] text-muted-foreground">{verifiedEvidence}/{evidenceCount} evidence events verified</div>
        </div>

        <div className="rounded-xl border p-4">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Executive outcome</div>
          <div className="mt-2 flex items-end justify-between"><span className="text-3xl font-black">{outcome}</span><span className="text-xs text-muted-foreground">/100</span></div>
          <div className="mt-2 text-xs font-semibold">{outcome >= 80 ? 'Strong outcome' : outcome >= 60 ? 'Positive outcome' : outcome >= 35 ? 'Limited outcome' : 'Insufficient outcome'}</div>
        </div>
      </div>

      <div className="grid gap-3 border-t px-5 py-4 text-xs sm:grid-cols-4">
        <Signal label="Risk" value={`${risk}/100`} delta={0} />
        <Signal label="Confidence" value={`${confidence}%`} delta={confidence >= 80 ? 1 : -1} inverse />
        <Signal label="Conflicts" value={String(conflicts)} delta={conflicts} />
        <Signal label="Decision" value={decisionState.replace('_', ' ')} delta={decisionState === 'resolved' ? 1 : 0} inverse />
      </div>
    </section>
  )
}

function Signal({ label, value, delta, inverse = false }: { label: string; value: string; delta: number; inverse?: boolean }) {
  const positive = inverse ? delta > 0 : delta < 0
  return <div className="rounded-lg border px-3 py-2"><div className="text-[10px] text-muted-foreground">{label}</div><div className="mt-1 flex items-center justify-between gap-2"><span className="font-semibold capitalize">{value}</span>{delta !== 0 && <span className={positive ? 'inline-flex items-center text-emerald-600' : 'inline-flex items-center text-amber-600'}>{delta > 0 ? <ArrowUpRight className="h-3 w-3" /> : <ArrowDownRight className="h-3 w-3" />}{Math.abs(delta)}</span>}</div></div>
}
