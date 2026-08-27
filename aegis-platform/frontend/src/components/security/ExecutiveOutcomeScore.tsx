import { CheckCircle2, Gauge, ShieldCheck, TrendingDown, TrendingUp, TriangleAlert } from 'lucide-react'

export type ExecutiveOutcomeScoreProps = {
  before: { risk: number; blastRadius: number; criticalFindings: number; confidence: number; affectedAssets: number }
  after: { risk: number; blastRadius: number; criticalFindings: number; confidence: number; affectedAssets: number }
  verified?: boolean
  evidenceCount?: number
  conflicts?: number
}

export function ExecutiveOutcomeScore({ before, after, verified = false, evidenceCount = 0, conflicts = 0 }: ExecutiveOutcomeScoreProps) {
  const riskGain = before.risk > 0 ? Math.max(0, Math.min(100, ((before.risk - after.risk) / before.risk) * 100)) : 0
  const blastGain = before.blastRadius > 0 ? Math.max(0, Math.min(100, ((before.blastRadius - after.blastRadius) / before.blastRadius) * 100)) : 0
  const criticalGain = before.criticalFindings > 0 ? Math.max(0, Math.min(100, ((before.criticalFindings - after.criticalFindings) / before.criticalFindings) * 100)) : 0
  const confidenceGain = Math.max(0, Math.min(100, after.confidence - before.confidence))
  const assuranceFactor = verified ? Math.min(1, 0.65 + Math.min(evidenceCount, 10) * 0.025) : Math.min(0.75, 0.35 + Math.min(evidenceCount, 10) * 0.04)
  const conflictPenalty = conflicts > 0 ? Math.min(35, conflicts * 8) : 0
  const raw = riskGain * 0.42 + blastGain * 0.22 + criticalGain * 0.18 + confidenceGain * 0.18
  const score = Math.max(0, Math.min(100, Math.round(raw * assuranceFactor - conflictPenalty)))
  const band = score >= 80 ? 'Strong outcome' : score >= 60 ? 'Positive outcome' : score >= 35 ? 'Limited outcome' : 'Insufficient outcome'
  const proven = verified && score >= 60 && conflicts === 0

  return <section className="overflow-hidden rounded-2xl border bg-card" aria-label="Executive outcome score">
    <header className="flex flex-wrap items-center justify-between gap-4 border-b px-5 py-4">
      <div><div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground"><Gauge className="h-4 w-4" /> Executive outcome score</div><h2 className="mt-1 text-lg font-bold tracking-tight">Measured remediation effectiveness</h2><p className="mt-1 text-xs text-muted-foreground">A decision-support score derived from outcome deltas, evidence strength and unresolved conflict pressure.</p></div><div className={`rounded-full border px-3 py-1.5 text-xs font-bold ${proven ? 'text-emerald-600' : 'text-amber-600'}`}>{proven ? 'Outcome proven' : band}</div></header>
    <div className="grid gap-5 p-5 lg:grid-cols-[220px_1fr]">
      <div className="grid place-items-center rounded-2xl border bg-muted/10 p-5"><div className="relative grid h-40 w-40 place-items-center rounded-full border-8 border-muted"><div className="absolute inset-0 rounded-full border-8 border-primary" style={{ clipPath: `inset(${100 - score}% 0 0 0)` }} /><div className="text-center"><div className="text-5xl font-black tracking-tight">{score}</div><div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">/ 100</div></div></div><div className="mt-3 text-xs font-semibold">{band}</div></div>
      <div className="space-y-3">
        <Factor label="Risk reduction" value={riskGain} weight="42%" good={riskGain > 0} icon={<TrendingDown className="h-4 w-4" />} />
        <Factor label="Blast radius reduction" value={blastGain} weight="22%" good={blastGain > 0} icon={<ShieldCheck className="h-4 w-4" />} />
        <Factor label="Critical exposure reduction" value={criticalGain} weight="18%" good={criticalGain > 0} icon={<TrendingDown className="h-4 w-4" />} />
        <Factor label="Confidence improvement" value={confidenceGain} weight="18%" good={confidenceGain > 0} icon={<CheckCircle2 className="h-4 w-4" />} />
        <div className="grid gap-2 pt-1 sm:grid-cols-2"><div className="rounded-xl border px-3 py-2 text-xs"><span className="text-muted-foreground">Evidence basis</span><div className="mt-1 font-bold">{evidenceCount} source{evidenceCount === 1 ? '' : 's'}</div></div><div className="rounded-xl border px-3 py-2 text-xs"><span className="text-muted-foreground">Conflict pressure</span><div className={`mt-1 font-bold ${conflicts ? 'text-amber-600' : 'text-emerald-600'}`}>{conflicts ? `${conflicts} unresolved` : 'None'}</div></div></div>
        <div className={`flex items-center gap-2 rounded-xl border px-3 py-2 text-[11px] ${proven ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300' : 'border-amber-500/30 bg-amber-500/5 text-amber-700 dark:text-amber-300'}`}><TriangleAlert className="h-4 w-4 shrink-0" />{proven ? 'The measured outcome is strong enough to support executive closure.' : verified ? 'Outcome measured, but executive closure still needs stronger assurance or conflict resolution.' : 'Executive outcome remains provisional until fresh validation evidence is available.'}</div>
      </div>
    </div>
  </section>
}

function Factor({ label, value, weight, good, icon }: { label: string; value: number; weight: string; good: boolean; icon: React.ReactNode }) {
  return <div className="rounded-xl border p-3"><div className="flex items-center gap-2"><span className={good ? 'text-emerald-600' : 'text-muted-foreground'}>{icon}</span><span className="flex-1 text-xs font-semibold">{label}</span><span className="text-[10px] text-muted-foreground">Weight {weight}</span><span className="text-xs font-bold">{Math.round(value)}%</span></div><div className="mt-2 h-1.5 overflow-hidden rounded-full bg-muted"><div className={`h-full rounded-full ${good ? 'bg-emerald-500' : 'bg-muted-foreground/30'}`} style={{ width: `${Math.round(value)}%` }} /></div></div>
}
