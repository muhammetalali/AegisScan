import { ArrowDownRight, ArrowUpRight, BriefcaseBusiness, CheckCircle2, TrendingDown, TrendingUp } from 'lucide-react'

export type ExecutiveImpactDiffProps = {
  before: { risk: number; blastRadius: number; criticalFindings: number; confidence: number; affectedAssets: number }
  after: { risk: number; blastRadius: number; criticalFindings: number; confidence: number; affectedAssets: number }
  verified?: boolean
}

function Delta({ before, after, inverse = false }: { before: number; after: number; inverse?: boolean }) {
  const delta = after - before
  const improved = inverse ? delta > 0 : delta < 0
  const Icon = delta === 0 ? null : delta > 0 ? ArrowUpRight : ArrowDownRight
  return <span className={`inline-flex items-center gap-1 text-[11px] font-semibold ${delta === 0 ? 'text-muted-foreground' : improved ? 'text-emerald-600' : 'text-amber-600'}`}>{Icon && <Icon className="h-3 w-3" />}{delta > 0 ? '+' : ''}{delta}</span>
}

export function ExecutiveImpactDiff({ before, after, verified = false }: ExecutiveImpactDiffProps) {
  const riskReduction = before.risk ? Math.round(((before.risk - after.risk) / before.risk) * 100) : 0
  const assetReduction = before.affectedAssets ? Math.round(((before.affectedAssets - after.affectedAssets) / before.affectedAssets) * 100) : 0
  const materiallyImproved = after.risk < before.risk && after.blastRadius <= before.blastRadius && after.criticalFindings <= before.criticalFindings

  return <section className="overflow-hidden rounded-2xl border bg-card" aria-label="Executive impact diff">
    <header className="flex flex-wrap items-center justify-between gap-3 border-b px-5 py-4">
      <div><div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground"><BriefcaseBusiness className="h-4 w-4" /> Executive impact diff</div><h2 className="mt-1 text-lg font-bold tracking-tight">Business risk before → after</h2><p className="mt-1 text-xs text-muted-foreground">Translate verified remediation into an executive-level outcome without creating a second risk model.</p></div>
      {verified && <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 px-3 py-1.5 text-xs font-bold text-emerald-600"><CheckCircle2 className="h-3.5 w-3.5" /> Outcome verified</span>}
    </header>
    <div className="grid gap-4 p-5 sm:grid-cols-2 lg:grid-cols-5">
      <Metric label="Risk exposure" before={before.risk} after={after.risk} suffix="/100" />
      <Metric label="Blast radius" before={before.blastRadius} after={after.blastRadius} suffix=" assets" />
      <Metric label="Critical findings" before={before.criticalFindings} after={after.criticalFindings} suffix="" />
      <Metric label="Confidence" before={before.confidence} after={after.confidence} suffix="%" inverse />
      <Metric label="Affected assets" before={before.affectedAssets} after={after.affectedAssets} suffix="" />
    </div>
    <div className="grid gap-4 border-t p-5 lg:grid-cols-[1fr_auto]">
      <div className="rounded-xl border bg-muted/10 p-4"><div className="flex items-center justify-between gap-3"><div><div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Executive outcome</div><div className="mt-1 text-sm font-bold">{materiallyImproved ? 'Material exposure reduction' : 'Impact requires review'}</div></div>{materiallyImproved ? <TrendingDown className="h-5 w-5 text-emerald-600" /> : <TrendingUp className="h-5 w-5 text-amber-600" />}</div><div className="mt-4 grid gap-3 sm:grid-cols-2"><div><div className="text-[10px] text-muted-foreground">Risk reduction</div><div className="mt-1 text-2xl font-black">{Math.max(0, riskReduction)}%</div></div><div><div className="text-[10px] text-muted-foreground">Asset exposure reduction</div><div className="mt-1 text-2xl font-black">{Math.max(0, assetReduction)}%</div></div></div></div>
      <div className="min-w-[210px] rounded-xl border p-4"><div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Executive signal</div><div className="mt-2 text-sm font-bold">{materiallyImproved ? 'Risk trajectory improved' : 'No proven improvement yet'}</div><p className="mt-1 text-[10px] leading-4 text-muted-foreground">{verified ? 'Fresh validation evidence supports this outcome.' : 'Awaiting fresh validation evidence before executive closure.'}</p></div>
    </div>
  </section>
}

function Metric({ label, before, after, suffix, inverse = false }: { label: string; before: number; after: number; suffix: string; inverse?: boolean }) {
  return <div className="rounded-xl border p-3"><div className="text-[10px] font-medium text-muted-foreground">{label}</div><div className="mt-3 flex items-end justify-between gap-2"><div><div className="text-[9px] uppercase text-muted-foreground">Before</div><div className="text-xl font-black">{before}{suffix}</div></div><div className="text-muted-foreground">→</div><div className="text-right"><div className="text-[9px] uppercase text-muted-foreground">After</div><div className="text-xl font-black">{after}{suffix}</div></div></div><div className="mt-2"><Delta before={before} after={after} inverse={inverse} /></div></div>
}
