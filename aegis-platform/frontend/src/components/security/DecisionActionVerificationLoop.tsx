import { useMemo, useState } from 'react'
import { CheckCircle2, CircleAlert, Play, ShieldCheck, Timer, Workflow } from 'lucide-react'

export type ActionVerificationState = 'planned' | 'ready' | 'executing' | 'verifying' | 'verified' | 'regressed'

export type DecisionActionVerificationLoopProps = {
  state?: ActionVerificationState
  owner?: string
  sla?: string
  expectedRiskReduction?: number
  riskBefore: number
  riskAfter?: number
  evidenceRequired?: number
  evidenceVerified?: number
  onExecute?: () => void
  onVerify?: () => void
}

const states: ActionVerificationState[] = ['planned', 'ready', 'executing', 'verifying', 'verified']

export function DecisionActionVerificationLoop({ state = 'ready', owner = 'Security Operations', sla = '24h', expectedRiskReduction = 0, riskBefore, riskAfter, evidenceRequired = 0, evidenceVerified = 0, onExecute, onVerify }: DecisionActionVerificationLoopProps) {
  const [active, setActive] = useState(state)
  const actualReduction = riskAfter == null ? 0 : Math.max(0, riskBefore - riskAfter)
  const verificationPct = evidenceRequired === 0 ? 0 : Math.min(100, Math.round((evidenceVerified / evidenceRequired) * 100))
  const outcome = useMemo(() => {
    if (active === 'regressed') return 'Regression detected'
    if (active === 'verified') return 'Fix verified'
    if (active === 'verifying') return 'Awaiting proof'
    if (active === 'executing') return 'Action executing'
    return 'Action ready'
  }, [active])

  const execute = () => { setActive('executing'); onExecute?.() }
  const verify = () => { setActive('verifying'); onVerify?.() }

  return (
    <section className="overflow-hidden rounded-2xl border bg-card" aria-label="Decision action verification loop">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b px-5 py-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground"><Workflow className="h-4 w-4" /> Decision → Action → Verification</div>
          <h2 className="mt-1 text-lg font-bold tracking-tight">Close the loop with measurable proof</h2>
          <p className="mt-1 text-xs text-muted-foreground">Execution is not resolution. Fresh evidence must prove the expected security outcome.</p>
        </div>
        <div className={`rounded-full border px-3 py-1.5 text-xs font-bold ${active === 'verified' ? 'text-emerald-600' : active === 'regressed' ? 'text-destructive' : 'text-amber-600'}`}>{outcome}</div>
      </header>

      <div className="grid gap-5 p-5 lg:grid-cols-[1.2fr_.8fr]">
        <div>
          <div className="grid gap-2 sm:grid-cols-5">
            {states.map((item, index) => {
              const reached = states.indexOf(active) >= index
              return <button key={item} type="button" onClick={() => setActive(item)} className={`rounded-xl border p-3 text-left transition ${active === item ? 'border-primary bg-primary/5 ring-2 ring-primary/10' : reached ? 'border-primary/20' : 'opacity-60 hover:opacity-100'}`}><div className="flex items-center gap-2">{reached ? <CheckCircle2 className="h-4 w-4" /> : <CircleAlert className="h-4 w-4" />}<span className="text-[10px] font-bold uppercase tracking-wider">{item}</span></div><div className="mt-1 text-[9px] text-muted-foreground">{index === 0 ? 'Decision created' : index === 1 ? 'Execution approved' : index === 2 ? 'Owner executing' : index === 3 ? 'Collect fresh proof' : 'Outcome confirmed'}</div></button>
            })}
          </div>

          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            <Metric label="Owner" value={owner} icon={<Workflow className="h-4 w-4" />} />
            <Metric label="SLA" value={sla} icon={<Timer className="h-4 w-4" />} />
            <Metric label="Expected reduction" value={`${Math.round(expectedRiskReduction)}%`} icon={<ShieldCheck className="h-4 w-4" />} />
          </div>
        </div>

        <div className="rounded-2xl border bg-muted/10 p-4">
          <div className="text-xs font-semibold">Outcome verification</div>
          <div className="mt-4 flex items-end justify-between"><div><div className="text-[9px] uppercase tracking-wider text-muted-foreground">Risk before</div><div className="text-3xl font-black">{Math.round(riskBefore)}</div></div><div className="text-muted-foreground">→</div><div className="text-right"><div className="text-[9px] uppercase tracking-wider text-muted-foreground">Risk after</div><div className="text-3xl font-black">{riskAfter == null ? '—' : Math.round(riskAfter)}</div></div></div>
          <div className="mt-4"><div className="flex justify-between text-[10px] text-muted-foreground"><span>Fresh evidence</span><span>{evidenceVerified}/{evidenceRequired}</span></div><div className="mt-2 h-2 overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full bg-primary transition-all" style={{ width: `${verificationPct}%` }} /></div></div>
          <div className="mt-4 rounded-xl border bg-background p-3 text-[10px] text-muted-foreground">{actualReduction > 0 ? `${Math.round(actualReduction)} risk points reduced.` : 'No verified reduction yet.'} Verification requires fresh evidence; a lower score alone does not close the finding.</div>
          <div className="mt-4 flex flex-wrap justify-end gap-2"><button type="button" onClick={execute} disabled={active === 'executing' || active === 'verifying' || active === 'verified'} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold disabled:opacity-40"><Play className="h-3.5 w-3.5" /> Execute action</button><button type="button" onClick={verify} disabled={active === 'verified'} className="inline-flex items-center gap-2 rounded-lg bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground disabled:opacity-40"><ShieldCheck className="h-3.5 w-3.5" /> Verify outcome</button></div>
        </div>
      </div>
    </section>
  )
}

function Metric({ label, value, icon }: { label: string; value: string; icon: React.ReactNode }) { return <div className="rounded-xl border p-3"><div className="flex items-center gap-2 text-muted-foreground">{icon}<span className="text-[10px] font-medium">{label}</span></div><div className="mt-1 truncate text-sm font-bold">{value}</div></div> }
