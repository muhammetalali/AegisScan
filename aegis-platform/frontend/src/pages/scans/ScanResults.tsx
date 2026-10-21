import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { Activity, AlertTriangle, FileText, ShieldCheck, Target } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { useLanguageStore } from '@/stores/languageStore'
import { cn } from '@/utils/cn'

type Scan = { id: string; asset_id?: string | null; project_id: string; name: string; scan_type: string; status: string; progress: number; current_phase: string; security_score: number; risk_level: string; findings_count: number; created_at: string; completed_at?: string | null }
type Asset = { id: string; name: string; type: string; configuration: Record<string, unknown> }
type Finding = { id: string; title: string; severity: string; status: string; observation_ip?: string | null; asset_name?: string | null; source_engine?: string | null; risk_score?: number | null }
type Evidence = { id: string; source: string; evidence_type: string; target?: string | null; sha256: string; collected_at: string; finding_id?: string | null }
type Execution = { id: string; engine: string; status: string; progress: number; findings_found: number; evidences_collected: number }

const textField = (...values: unknown[]) => values.find((v): v is string => typeof v === 'string' && v.trim().length > 0) || null
const macPattern = /^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i

/** Always resolve identity from the authorized asset, not from a free-form scan title. */
export function scanTargetIdentity(scan: Scan, asset?: Asset | null) {
  const config = asset?.configuration || {}
  const target = textField(config.ip, config.cidr, config.url, config.domain, config.hostname, config.target)
  const rawMac = textField(config.mac_address, config.mac, config.macAddress)
  return { target, mac: rawMac && macPattern.test(rawMac) ? rawMac.toUpperCase().replace(/-/g, ':') : null }
}

const tone = (severity: string) => ({
  critical: 'border-red-500/25 bg-red-500/10 text-red-600',
  high: 'border-orange-500/25 bg-orange-500/10 text-orange-600',
  medium: 'border-amber-500/25 bg-amber-500/10 text-amber-600',
  low: 'border-emerald-500/25 bg-emerald-500/10 text-emerald-600',
}[severity.toLowerCase()] || 'border-border bg-muted/20 text-muted-foreground')

const Metric = ({ label, value }: { label: string; value: string }) => (
  <div className="rounded-xl border bg-background/20 p-3">
    <div className="text-xs text-muted-foreground">{label}</div>
    <div className="mt-1 text-lg font-semibold tabular-nums">{value}</div>
  </div>
)
const State = ({ children }: { children: React.ReactNode }) => (
  <div className="rounded-xl border border-dashed p-6 text-center text-sm text-muted-foreground">{children}</div>
)

export const ScanResults = () => {
  const t = useLanguageStore((state) => state.t)
  const { id } = useParams<{ id: string }>()
  const scan = useQuery<Scan>({ queryKey: ['scan-result-meta', id], queryFn: () => apiHelpers.get<Scan>('/scans/' + id), enabled: Boolean(id) })
  const asset = useQuery<Asset>({ queryKey: ['scan-result-asset', scan.data?.asset_id], queryFn: () => apiHelpers.get<Asset>('/assets/' + scan.data?.asset_id), enabled: Boolean(scan.data?.asset_id) })
  const findings = useQuery<Finding[]>({ queryKey: ['scan-result-findings', id], queryFn: () => apiHelpers.get<Finding[]>('/vulnerabilities/?scan_id=' + encodeURIComponent(id || '') + '&limit=200'), enabled: Boolean(id) })
  const evidence = useQuery<Evidence[]>({ queryKey: ['scan-result-evidence', id], queryFn: () => apiHelpers.get<Evidence[]>('/evidence/?scan_id=' + encodeURIComponent(id || '') + '&limit=200'), enabled: Boolean(id) })
  const executions = useQuery<Execution[]>({ queryKey: ['scan-result-executions', id], queryFn: () => apiHelpers.get<Execution[]>('/scans/' + id + '/engine-executions'), enabled: Boolean(id) })

  if (scan.isLoading) return <div className="space-y-4"><div className="h-28 animate-pulse rounded-3xl bg-muted" /><div className="h-72 animate-pulse rounded-3xl bg-muted" /></div>
  if (scan.isError || !scan.data) return (
    <div className="enterprise-card rounded-3xl p-10 text-center">
      <AlertTriangle className="mx-auto h-8 w-8 text-destructive" />
      <h1 className="mt-3 font-semibold">{t('Unable to load scan')}</h1>
      <Link to="/scan" className="mt-4 inline-flex rounded-xl border px-4 py-2 text-sm">{t('Back to scans')}</Link>
    </div>
  )

  const s = scan.data
  const identity = scanTargetIdentity(s, asset.data)
  const targetLabel = s.scan_type === 'network' ? t('Network range') : s.scan_type === 'ip' ? t('IP address') : t('Target')
  const score = s.risk_level && s.risk_level !== 'unknown' ? String(s.security_score) : t('Not assessed')

  return <div className="space-y-5 pb-10">
    <section className="enterprise-card rounded-3xl p-6 md:p-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-bold text-primary"><ShieldCheck className="h-4 w-4" />{t('Scan results')}</div>
          <p className="mt-3 text-xs text-muted-foreground">{targetLabel}</p>
          <h1 dir="ltr" className="mt-1 break-all text-start text-2xl font-semibold tracking-tight md:text-3xl">
            {identity.target || (asset.isLoading ? t('Loading...') : t('Target not recorded'))}
          </h1>
          <div className="mt-3 flex flex-wrap gap-4 text-sm">
            <span><span className="text-muted-foreground">{t('MAC address')}: </span><span dir="ltr" className="font-mono">{identity.mac || t('Not recorded')}</span></span>
          </div>
          <p className="mt-3 max-w-2xl text-sm text-muted-foreground">{t('This page shows detected services, findings and saved evidence for the authorized target.')}</p>
        </div>
        <span className="rounded-full border px-3 py-1.5 text-sm font-semibold">{t('Status')}: {s.status}</span>
      </div>
      <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label={t('Findings')} value={String(s.findings_count ?? '—')} />
        <Metric label={t('Evidence records')} value={evidence.data ? String(evidence.data.length) : '—'} />
        <Metric label={t('Progress')} value={String(s.progress ?? 0) + '%'} />
        <Metric label={t('Risk assessment')} value={score} />
      </div>
      <p className="mt-3 text-xs text-muted-foreground">{t('An exposed port is not automatically a confirmed vulnerability.')}</p>
      <details className="mt-4 rounded-xl border bg-muted/10 p-3 text-xs">
        <summary className="cursor-pointer font-semibold">{t('Technical details')}</summary>
        <div className="mt-3 space-y-2 text-muted-foreground">
          <div>{t('Original scan name')}: <span className="break-all text-foreground">{s.name}</span></div>
          <div>{t('Scan ID')}: <code dir="ltr" className="select-all break-all">{s.id}</code></div>
          <div>{t('Engine phase')}: {s.current_phase || t('Not reported')}</div>
          <div>{t('Asset ID')}: <code dir="ltr" className="select-all break-all">{s.asset_id || t('Not linked')}</code></div>
        </div>
      </details>
    </section>

    <div className="grid gap-4 xl:grid-cols-3">
      <section className="enterprise-card rounded-2xl p-5 xl:col-span-2">
        <div className="mb-4 flex items-center gap-2"><Target className="h-4 w-4 text-primary" /><h2 className="font-semibold">{t('Findings')}</h2></div>
        <p className="mb-4 text-xs text-muted-foreground">{t('Select any finding to see its recorded details.')}</p>
        {findings.isLoading ? <State>{t('Loading...')}</State> : findings.isError ? <State>{t('Unable to load findings')}</State> : !findings.data?.length ? <State>{t('No findings available')}</State> : (
          <div className="max-h-[640px] space-y-2 overflow-y-auto">
            {findings.data.map((finding) => (
              <Link key={finding.id} to={'/vulnerabilities/' + finding.id} className="block rounded-xl border p-3 transition-colors hover:bg-muted/30">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={cn('rounded-full border px-2 py-1 text-xs font-semibold', tone(finding.severity))}>{finding.severity}</span>
                  {finding.observation_ip ? <span dir="ltr" className="rounded-md bg-muted px-2 py-1 font-mono text-xs" title={t('Observed host')}>{finding.observation_ip}</span> : null}
                  <span className="font-semibold">{finding.title}</span>
                </div>
                <div className="mt-1 text-xs text-muted-foreground">{finding.source_engine || t('Not reported')} · {finding.status}</div>
              </Link>
            ))}
          </div>
        )}
      </section>
      <section className="enterprise-card rounded-2xl p-5">
        <div className="mb-4 flex items-center gap-2"><Activity className="h-4 w-4 text-primary" /><h2 className="font-semibold">{t('Engine executions')}</h2></div>
        <p className="mb-4 text-xs text-muted-foreground">{t('Shows which scanner ran and whether it finished.')}</p>
        {executions.isLoading ? <State>{t('Loading...')}</State> : executions.isError ? <State>{t('Unable to load engine executions')}</State> : !executions.data?.length ? <State>{t('No engine executions reported')}</State> : (
          <div className="space-y-3">{executions.data.map((execution) => <div className="rounded-xl border p-3" key={execution.id}>
            <div className="flex items-center justify-between gap-2"><strong>{execution.engine}</strong><span className="text-xs text-muted-foreground">{execution.status}</span></div>
            <div className="mt-3 grid grid-cols-2 gap-2"><Metric label={t('Progress')} value={String(execution.progress) + '%'} /><Metric label={t('Scanner outputs')} value={String(execution.evidences_collected)} /></div>
          </div>)}</div>
        )}
      </section>
    </div>

    <section className="enterprise-card rounded-2xl p-5">
      <div className="flex items-center gap-2"><FileText className="h-4 w-4 text-primary" /><h2 className="font-semibold">{t('Evidence')}</h2></div>
      <p className="mt-2 text-sm text-muted-foreground">{t('Evidence records link each finding to stored scanner output. Open an item to view its integrity details.')}</p>
      {evidence.isLoading ? <State>{t('Loading...')}</State> : evidence.isError ? <State>{t('Unable to load evidence')}</State> : !evidence.data?.length ? <State>{t('No evidence available')}</State> : (
        <details className="mt-4 rounded-xl border p-4">
          <summary className="cursor-pointer text-sm font-semibold">{t('View evidence records')} ({evidence.data.length})</summary>
          <div className="mt-3 max-h-[480px] space-y-2 overflow-y-auto">
            {evidence.data.map((item, index) => <details key={item.id} className="rounded-lg border bg-muted/10 p-3 text-xs">
              <summary className="cursor-pointer font-medium">{t('Evidence')} {index + 1} · {item.source}</summary>
              <div className="mt-3 space-y-2 break-all text-muted-foreground">
                <p>{t('Type')}: {item.evidence_type}</p>
                <p>{t('Finding')}: <code dir="ltr" className="select-all">{item.finding_id || t('Not linked')}</code></p>
                <p>SHA-256: <code dir="ltr" className="select-all">{item.sha256}</code></p>
                <p>{t('Collected')}: {new Date(item.collected_at).toLocaleString()}</p>
              </div>
            </details>)}
          </div>
        </details>
      )}
    </section>
    <div className="flex justify-end"><Link to="/scan" className="rounded-xl border px-4 py-2.5 text-sm font-semibold">{t('Back to scans')}</Link></div>
  </div>
}
