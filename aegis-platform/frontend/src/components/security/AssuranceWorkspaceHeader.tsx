import { Activity, ShieldCheck } from 'lucide-react'

type AssuranceWorkspaceHeaderProps = {
  eyebrow?: string
  title: string
  description: string
  live?: boolean
  actions?: React.ReactNode
}

export function AssuranceWorkspaceHeader({
  eyebrow = 'Assurance intelligence',
  title,
  description,
  live = true,
  actions,
}: AssuranceWorkspaceHeaderProps) {
  return (
    <header className="relative overflow-hidden rounded-2xl border bg-card/80 p-5 shadow-sm backdrop-blur-xl md:p-6">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(56,189,248,0.10),transparent_34%),radial-gradient(circle_at_bottom_left,rgba(99,102,241,0.08),transparent_32%)]" />
      <div className="relative flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
        <div className="max-w-3xl">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-full border bg-background/70 px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground">
              <ShieldCheck className="h-3 w-3" />
              {eyebrow}
            </span>
            {live && (
              <span className="inline-flex items-center gap-1.5 rounded-full border bg-background/70 px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.14em] text-emerald-600 dark:text-emerald-400">
                <Activity className="h-3 w-3" />
                Live fabric
              </span>
            )}
          </div>
          <h1 className="text-2xl font-black tracking-[-0.03em] md:text-3xl">{title}</h1>
          <p className="mt-2 text-sm leading-6 text-muted-foreground">{description}</p>
        </div>
        {actions ? <div className="relative flex shrink-0 flex-wrap gap-2">{actions}</div> : null}
      </div>
    </header>
  )
}
