import { useQuery } from '@tanstack/react-query'
import { FileText, RefreshCw, ShieldCheck } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { normalizeAssuranceModel } from '@/components/security/SecurityAssuranceModel'

export const Reports = () => {
  const query = useQuery({ queryKey: ['reports-center'], queryFn: async () => {
    const [summary, risk, reports] = await Promise.all([
      apiHelpers.get<any>('/dashboard/summary'),
      apiHelpers.get<any>('/dashboard/risk-distribution'),
      apiHelpers.get<any>('/reports/'),
    ])
    const items = Array.isArray(reports) ? reports : reports?.results ?? reports?.items ?? []
    return { model: normalizeAssuranceModel(summary, risk), items }
  }})

  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading report center…</div>
  if (query.error || !query.data) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Report center unavailable</h1><p className="mt-2 text-sm text-muted-foreground">Live assurance data is required. No synthetic reports are shown.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>

  const { model, items } = query.data
  return <div className="space-y-5"><header><div className="flex items-center gap-2"><FileText className="h-6 w-6 text-primary" /><h1 className="text-2xl font-bold">Reports</h1></div><p className="mt-1 text-sm text-muted-foreground">One assurance model powers technical, management, and executive reporting.</p></header><section className="grid gap-3 md:grid-cols-4"><Metric label="Security score" value={`${model.securityScore}/100`} /><Metric label="Critical" value={model.critical} /><Metric label="Control coverage" value={`${model.controlCoverage}%`} /><Metric label="Remediation" value={`${model.remediationRate}%`} /></section><section className="rounded-2xl border bg-card overflow-hidden"><div className="border-b px-5 py-4"><div className="flex items-center gap-2 font-semibold"><ShieldCheck className="h-4 w-4 text-primary" /> Generated reports</div><p className="mt-1 text-xs text-muted-foreground">Reports inherit the same risk, compliance, evidence, and validation context.</p></div>{items.length ? <div className="divide-y">{items.map((item: any, index: number) => <div key={item.id ?? index} className="flex flex-wrap items-center gap-3 px-5 py-4"><div className="min-w-0 flex-1"><div className="text-sm font-semibold">{item.title ?? item.name ?? `Security report ${index + 1}`}</div><div className="mt-1 text-xs text-muted-foreground">{item.report_type ?? item.type ?? 'security assurance'} · {item.status ?? 'available'}</div></div><a href={`/reports/${item.id}`} className="rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted">Open</a></div>)}</div> : <div className="p-10 text-center text-sm text-muted-foreground">No reports are available yet.</div>}</section><div className="rounded-xl border bg-muted/10 p-4 text-xs text-muted-foreground">Executive and detailed report views intentionally consume the normalized assurance model rather than maintaining a second source of truth.</div></div>
}
function Metric({ label, value }: { label: string; value: string | number }) { return <div className="rounded-xl border bg-card p-4"><div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div><div className="mt-1 text-xl font-black">{value}</div></div> }
