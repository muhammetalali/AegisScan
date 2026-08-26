import { ArrowRight, FileSearch, ShieldAlert, Target, Waypoints } from 'lucide-react'

const steps = [
  { key: 'risk', label: 'Risk', detail: 'Score & exposure', icon: Target },
  { key: 'attack', label: 'Attack Path', detail: 'Propagation', icon: Waypoints },
  { key: 'blast', label: 'Blast Radius', detail: 'Affected surface', icon: ShieldAlert },
  { key: 'evidence', label: 'Evidence', detail: 'Validation chain', icon: FileSearch },
] as const

export function UnifiedInvestigationFlow({ active = 'attack', onNavigate }: { active?: (typeof steps)[number]['key']; onNavigate?: (key: (typeof steps)[number]['key']) => void }) {
  return <section className="rounded-2xl border bg-card p-4"><div className="mb-3 flex items-center justify-between gap-3"><div><div className="text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">Investigation flow</div><p className="mt-1 text-[11px] text-muted-foreground">One selection, one investigation context — every layer stays synchronized.</p></div><div className="rounded-full border px-2.5 py-1 text-[10px] font-semibold text-muted-foreground">Unified context</div></div><div className="grid gap-2 md:grid-cols-7 md:items-center">{steps.map((step, index) => { const Icon = step.icon; const isActive = active === step.key; return <div key={step.key} className="contents"><button type="button" onClick={() => onNavigate?.(step.key)} aria-current={isActive ? 'step' : undefined} className={`group rounded-xl border p-3 text-left transition ${isActive ? 'border-primary/40 bg-primary/5 shadow-[0_0_24px_hsl(var(--primary)/.08)]' : 'hover:bg-muted/60'}`}><div className="flex items-center gap-2"><span className={`grid h-8 w-8 place-items-center rounded-lg border ${isActive ? 'bg-primary/10 text-primary' : 'bg-background'}`}><Icon className="h-4 w-4" /></span><span className="min-w-0"><span className="block truncate text-xs font-semibold">{step.label}</span><span className="block truncate text-[10px] text-muted-foreground">{step.detail}</span></span></div></button>{index < steps.length - 1 && <ArrowRight className="mx-auto hidden h-4 w-4 text-muted-foreground/40 md:block" />}</div> })}</div></section>
}
