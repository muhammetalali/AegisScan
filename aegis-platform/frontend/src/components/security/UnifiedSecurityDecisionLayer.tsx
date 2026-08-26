import { CheckCircle2, CircleAlert, FileSearch, ShieldAlert, TrendingDown, TrendingUp, Wrench } from 'lucide-react'

export type DecisionState = 'verified' | 'needs-remediation' | 'revalidation-required' | 'unknown'

export function UnifiedSecurityDecisionLayer({ state, riskBefore, riskAfter, evidenceCount, affectedAssets, onInvestigate, onRemediate, onRevalidate }: { state: DecisionState; riskBefore: number; riskAfter: number; evidenceCount: number; affectedAssets: number; onInvestigate?: () => void; onRemediate?: () => void; onRevalidate?: () => void }) {
  const delta = riskAfter - riskBefore
  const improved = delta < 0
  const config = {
    verified: { label: 'Verified', icon: CheckCircle2, text: 'Current evidence supports the remediation outcome.' },
    'needs-remediation': { label: 'Needs remediation', icon: ShieldAlert, text: 'The observed risk remains material and requires corrective action.' },
    'revalidation-required': { label: 'Re-validation required', icon: FileSearch, text: 'A fix was applied, but fresh validation evidence is still required.' },
    unknown: { label: 'Insufficient evidence', icon: CircleAlert, text: 'The current evidence chain is not sufficient to make a verification decision.' },
  }[state]
  const StatusIcon = config.icon
  return <section className="overflow-hidden rounded-2xl border bg-card"><div className="flex flex-wrap items-center justify-between gap-4 border-b px-5 py-4"><div><div className="flex items-center gap-2 text-xs font-semibold"><StatusIcon className="h-4 w-4 text-primary" /> Security decision</div><p className="mt-1 text-sm font-semibold">{config.label}</p><p className="mt-1 max-w-2xl text-[11px] text-muted-foreground">{config.text}</p></div><div className="flex gap-2"><button type="button" onClick={onInvestigate} className="rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted">Investigate</button>{state === 'needs-remediation' && <button type="button" onClick={onRemediate} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><Wrench className="h-3.5 w-3.5" /> Remediate</button>}{state === 'revalidation-required' && <button type="button" onClick={onRevalidate} className="inline-flex items-center gap-2 rounded-lg bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground"><FileSearch className="h-3.5 w-3.5" /> Re-validate</button>}</div></div><div className="grid grid-cols-2 divide-x md:grid-cols-4"><Stat label="Risk before" value={riskBefore} /><Stat label="Risk after" value={riskAfter} /><Stat label="Evidence" value={evidenceCount} /><Stat label="Affected assets" value={affectedAssets} /></div><div className="border-t bg-muted/10 px-5 py-3"><div className="flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">{improved ? <TrendingDown className="h-3.5 w-3.5 text-emerald-600" /> : <TrendingUp className="h-3.5 w-3.5 text-destructive" />}<span className="font-semibold">Risk delta: {delta > 0 ? '+' : ''}{delta}</span><span>·</span><span>Decision should be grounded in fresh validation evidence.</span></div></div></section>
}
function Stat({ label, value }: { label: string; value: number }) { return <div className="px-5 py-3"><div className="text-[9px] uppercase tracking-wider text-muted-foreground">{label}</div><div className="mt-1 text-lg font-bold">{value}</div></div> }
