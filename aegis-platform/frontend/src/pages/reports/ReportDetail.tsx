import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Download, FileText, RefreshCw, ShieldCheck } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import { apiHelpers } from '@/services/api'
import { normalizeAssuranceModel } from '@/components/security/SecurityAssuranceModel'

export const ReportDetail = () => {
  const { id } = useParams<{ id: string }>()
  const query = useQuery({ queryKey: ['report-detail', id], queryFn: async () => {
    const [summary, risk, report] = await Promise.all([
      apiHelpers.get<any>('/dashboard/summary'),
      apiHelpers.get<any>('/dashboard/risk-distribution'),
      apiHelpers.get<any>(`/reports/${id}`),
    ])
    return { model: normalizeAssuranceModel(summary, risk), report }
  }, enabled: !!id })

  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading report…</div>
  if (query.error || !query.data) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Report unavailable</h1><p className="mt-2 text-sm text-muted-foreground">The report could not be loaded from the live API.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>

  const { model, report } = query.data
  const title = report?.title ?? report?.name ?? 'Security Assurance Report'
  return <div className="space-y-5"><div className="flex flex-wrap items-center justify-between gap-3"><Link to="/reports" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground"><ArrowLeft className="h-4 w-4" /> Reports</Link><button type="button" className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><Download className="h-3.5 w-3.5" /> Export</button></div><section className="rounded-2xl border bg-card p-6"><div className="flex items-start gap-3"><div className="grid h-11 w-11 place-items-center rounded-xl border bg-primary/5"><FileText className="h-5 w-5 text-primary" /></div><div><div className="text-[10px] uppercase tracking-[0.16em] text-muted-foreground">Assurance report</div><h1 className="mt-1 text-2xl font-bold">{title}</h1><p className="mt-1 text-sm text-muted-foreground">A report projection of the same security assurance model used by posture and executive views.</p></div></div><div className="mt-6 grid gap-3 md:grid-cols-4"><Metric label="Security score" value={`${model.securityScore}/100`} /><Metric label="Critical" value={model.critical} /><Metric label="High" value={model.high} /><Metric label="Control coverage" value={`${model.controlCoverage}%`} /></div></section><section className="grid gap-5 lg:grid-cols-2"><Panel title="Risk & assurance"><Row label="Risk exposure" value={model.riskExposure} /><Row label="Validation coverage" value={`${model.validationCoverage}%`} /><Row label="Remediation rate" value={`${model.remediationRate}%`} /><Row label="Open exceptions" value={model.openExceptions} /></Panel><Panel title="Report provenance"><div className="flex items-center gap-2 text-sm font-semibold"><ShieldCheck className="h-4 w-4 text-primary" /> Same source-of-truth model</div><p className="mt-2 text-xs leading-5 text-muted-foreground">Risk, findings, controls, evidence, validation, and executive impact are intended to converge on one normalized assurance context.</p></Panel></section></div>
}
function Metric({ label, value }: { label: string; value: string | number }) { return <div className="rounded-xl border bg-muted/10 p-4"><div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div><div className="mt-1 text-xl font-black">{value}</div></div> }
function Panel({ title, children }: { title: string; children: React.ReactNode }) { return <section className="rounded-2xl border bg-card p-5"><h2 className="font-semibold">{title}</h2><div className="mt-4">{children}</div></section> }
function Row({ label, value }: { label: string; value: string | number }) { return <div className="flex items-center justify-between border-b py-3 text-sm last:border-b-0"><span className="text-muted-foreground">{label}</span><span className="font-semibold">{value}</span></div> }
