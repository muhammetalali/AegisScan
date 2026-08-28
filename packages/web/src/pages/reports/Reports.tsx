import { useQuery } from '@tanstack/react-query'
import { FileText, RefreshCw, ShieldCheck } from 'lucide-react'
import { Link } from 'react-router-dom'
import { apiHelpers } from '@/services/api'
import { normalizeAssuranceModel } from '@/components/security/SecurityAssuranceModel'

export const Reports = () => {
  const summaryQuery = useQuery({ queryKey: ['reports-summary'], queryFn: () => apiHelpers.get<any>('/dashboard/summary'), staleTime: 10_000 })
  const riskQuery = useQuery({ queryKey: ['reports-risk'], queryFn: () => apiHelpers.get<any>('/dashboard/risk-distribution'), staleTime: 10_000 })
  const reportsQuery = useQuery({ queryKey: ['reports-center-items'], queryFn: () => apiHelpers.get<any>('/reports/'), staleTime: 10_000 })
  if (summaryQuery.isLoading || riskQuery.isLoading || reportsQuery.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading report center…</div>

  const summaryOk = !summaryQuery.error && !!summaryQuery.data
  const riskOk = !riskQuery.error && !!riskQuery.data
  const reportsResponse = reportsQuery.data
  const items = Array.isArray(reportsResponse) ? reportsResponse : reportsResponse?.results ?? reportsResponse?.items ?? []
  const model = summaryOk && riskOk ? normalizeAssuranceModel(summaryQuery.data, riskQuery.data) : null

  return <div className="space-y-5"><header><div className="flex items-center gap-2"><FileText className="h-6 w-6 text-primary" /><h1 className="text-2xl font-bold">Reports</h1></div><p className="mt-1 text-sm text-muted-foreground">Technical, management and executive reports use the same live assurance context.</p></header>
    {(!summaryOk || !riskOk) && <Notice title="Assurance summary is incomplete" detail="Current posture metrics are unavailable because one or more live dashboard datasets did not respond." onRetry={() => { void summaryQuery.refetch(); void riskQuery.refetch() }} />}
    {summaryOk && riskOk && model && <section className="grid gap-3 md:grid-cols-4"><Metric label="Security score" value={`${model.securityScore}/100`} /><Metric label="Critical" value={model.critical} /><Metric label="Control coverage" value={`${model.controlCoverage}%`} /><Metric label="Remediation" value={`${model.remediationRate}%`} /></section>}
    <section className="rounded-2xl border bg-card overflow-hidden"><div className="border-b px-5 py-4"><div className="flex items-center gap-2 font-semibold"><ShieldCheck className="h-4 w-4 text-primary" /> Generated reports</div><p className="mt-1 text-xs text-muted-foreground">Only persisted reports returned by the live Reports API are shown.</p></div>{reportsQuery.error ? <div className="p-10 text-center"><p className="font-medium">Reports could not be loaded</p><p className="mt-1 text-sm text-muted-foreground">The Reports API did not return a usable response.</p><button type="button" onClick={() => reportsQuery.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div> : items.length ? <div className="divide-y">{items.map((item: any) => <div key={item.id} className="flex flex-wrap items-center gap-3 px-5 py-4"><div className="min-w-0 flex-1"><div className="text-sm font-semibold">{item.title ?? item.name ?? 'Untitled report'}</div><div className="mt-1 text-xs text-muted-foreground">{item.report_type ?? item.type ?? 'report'} · {item.status ?? 'unknown'} {item.format ? `· ${String(item.format).toUpperCase()}` : ''}</div></div>{item.id && <Link to={`/reports/${item.id}`} className="rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted">Open</Link>}</div>)}</div> : <div className="p-10 text-center text-sm text-muted-foreground">No persisted reports are available yet. Generate a report from a validation or schedule to populate this center.</div>}</section>
  </div>
}
function Notice({ title, detail, onRetry }: { title: string; detail: string; onRetry: () => void }) { return <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><p className="font-medium">{title}</p><p className="mt-1 text-sm text-muted-foreground">{detail}</p></div><button type="button" onClick={onRetry} className="inline-flex items-center gap-2 rounded-lg border bg-card px-3 py-2 text-xs font-semibold"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div> }
function Metric({ label, value }: { label: string; value: string | number }) { return <div className="rounded-xl border bg-card p-4"><div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div><div className="mt-1 text-xl font-black">{value}</div></div> }