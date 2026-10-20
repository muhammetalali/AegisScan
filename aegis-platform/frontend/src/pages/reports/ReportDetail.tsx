import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Download, FileText, RefreshCw, ShieldCheck } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import { apiHelpers } from '@/services/api'
import { useLanguageStore } from '@/stores/languageStore'

type Report = {
  id: string; title: string; project_id: string; scan_id?: string | null
  report_type: string; format: string; status: string; created_at: string
  completed_at?: string | null; expires_at?: string
  file_size?: number; artifact_sha256?: string
}
type Scan = { id: string; status?: string; findings_count?: number; asset?: { configuration?: { ip?: string; url?: string; cidr?: string } } }

const typeDescription: Record<string, string> = {
  full: 'A complete report brings together available scans, findings and saved evidence for the authorized project.',
  findings: 'A findings report records detected security issues and available classification and evidence.',
  evidence: 'An evidence report preserves scanner observations and their provenance for later verification.',
  scan: 'A scan report documents the target, execution and the observations saved for that scan.',
  wstg: 'A WSTG report records available web-testing observations and their supporting evidence.',
}
export const describeReportType = (type: string) =>
  typeDescription[type] || 'This report contains the saved data available for its selected report type.'

export const ReportDetail = () => {
  const t = useLanguageStore((state) => state.t)
  const { id } = useParams<{ id: string }>()
  const reportQuery = useQuery<Report>({ queryKey: ['report-detail', id], queryFn: () => apiHelpers.get<Report>(`/reports/${id}`), enabled: !!id })
  const report = reportQuery.data
  const scanQuery = useQuery<Scan>({ queryKey: ['report-linked-scan', report?.scan_id], queryFn: () => apiHelpers.get<Scan>(`/scans/${report?.scan_id}`), enabled: Boolean(report?.scan_id), retry: false })
  if (reportQuery.isLoading) return <p className="p-8 text-sm">{t('Loading report…')}</p>
  if (reportQuery.isError || !report) return <section className="mx-auto max-w-xl rounded-2xl border bg-card p-8 text-center">
    <h1 className="text-lg font-semibold">{t('Report unavailable')}</h1>
    <p className="mt-2 text-sm text-muted-foreground">{t('The report could not be loaded from the live API.')}</p>
    <button type="button" onClick={() => reportQuery.refetch()} className="mt-4 rounded-lg border px-3 py-2">{t('Retry')}</button>
  </section>

  const scan = scanQuery.data
  const target = scan?.asset?.configuration?.ip || scan?.asset?.configuration?.url || scan?.asset?.configuration?.cidr
  return <div className="mx-auto max-w-5xl space-y-5 pb-10">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <Link to="/reports" className="inline-flex items-center gap-2 text-sm"><ArrowLeft className="h-4 w-4" />{t('Reports')}</Link>
      <button type="button" onClick={() => window.open(`/api/v1/reports/${report.id}/download`, '_blank', 'noopener,noreferrer')}
        disabled={report.status !== 'completed'}
        className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-50">
        <Download className="h-4 w-4" />{t('Download complete report')}
      </button>
    </div>
    <section className="enterprise-card rounded-2xl p-6">
      <div className="flex items-center gap-2 text-sm font-semibold text-primary"><FileText className="h-5 w-5"/>{t('Security assessment report')}</div>
      <h1 className="mt-3 break-words text-2xl font-bold">{report.title}</h1>
      <p className="mt-3 text-sm leading-7 text-muted-foreground">{t(describeReportType(report.report_type))}</p>
      <div className="mt-4 inline-flex items-center gap-2 text-sm"><ShieldCheck className="h-4 w-4 text-primary"/>{t('Status')}: {t(report.status)} · {report.format.toUpperCase()}</div>
    </section>
    <section className="grid gap-4 md:grid-cols-2">
      <article className="enterprise-card rounded-2xl p-5">
        <h2 className="text-lg font-semibold">{t('What does this report tell me?')}</h2>
        <p className="mt-3 text-sm leading-7 text-muted-foreground">{t('It records observations from the selected scope. An exposed port or informational result is not automatically an exploitable vulnerability. Confirm risk from finding evidence and validation.')}</p>
        {typeof scan?.findings_count === 'number' && <p className="mt-3 text-sm">{t('Recorded findings in the linked scan')}: <strong>{scan.findings_count}</strong></p>}
        {target && <p className="mt-2 break-all text-sm">{t('Scanned target')}: <strong dir="ltr">{target}</strong></p>}
        {report.scan_id && <Link to={`/scan/${encodeURIComponent(report.scan_id)}/results`} className="mt-4 inline-block text-sm font-semibold text-primary">{t('Open linked scan and evidence')} →</Link>}
        {report.scan_id && scanQuery.isError && <p className="mt-2 text-sm text-muted-foreground">{t('Linked scan details are not currently available. The report record remains available.')}</p>}
      </article>
      <article className="enterprise-card rounded-2xl p-5">
        <h2 className="text-lg font-semibold">{t('How to interpret the findings')}</h2>
        <div className="mt-3 space-y-3 text-sm leading-7 text-muted-foreground">
          <p>{t('Where: review the affected IP, URL, service or file in each finding.')}</p>
          <p>{t('Impact: use the recorded evidence and validation status. Do not treat a scanner observation as proof of exploitation.')}</p>
          <p>{t('Action: apply the recommended correction, then perform an authorized verification before closing the finding.')}</p>
        </div>
        <p className="mt-4 text-sm">{t('Use the Download button to read the full saved report in its original format.')}</p>
      </article>
    </section>
    <details className="enterprise-card rounded-2xl p-5">
      <summary className="cursor-pointer text-sm font-semibold">{t('Technical report provenance (optional)')}</summary>
      <dl className="mt-4 grid gap-3 text-sm">
        <div><dt className="text-muted-foreground">{t('Report ID')}</dt><dd className="break-all font-mono text-xs">{report.id}</dd></div>
        <div><dt className="text-muted-foreground">{t('Project')}</dt><dd className="break-all font-mono text-xs">{report.project_id}</dd></div>
        <div><dt className="text-muted-foreground">{t('Created')}</dt><dd>{new Date(report.created_at).toLocaleString()}</dd></div>
        {report.artifact_sha256 && <div><dt className="text-muted-foreground">SHA-256</dt><dd className="break-all font-mono text-xs">{report.artifact_sha256}</dd></div>}
      </dl>
    </details>
  </div>
}
