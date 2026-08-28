import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Activity, Database, ExternalLink, Loader2, ShieldAlert, Sparkles } from 'lucide-react'
import { apiHelpers } from '@/services/api'

interface Provider { id: string; status: string }
interface IntelligenceRecord {
  cve_id: string
  severity: string
  cvss: number | null
  epss: number | null
  kev: boolean
  risk_score: number
  confidence: number
  matched_assets: string[]
  evidence: Array<{ source: string; type: string; url?: string; value?: number }>
  provider_status?: Record<string, string>
  cache?: 'hit' | 'miss'
}

export function IntelligencePanel() {
  const [cve, setCve] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const providersQuery = useQuery({
    queryKey: ['intelligence-providers'],
    queryFn: () => apiHelpers.get<{ providers: Provider[] }>('/intelligence/providers'),
    staleTime: 60_000,
    retry: 1,
  })
  const enrichQuery = useQuery({
    queryKey: ['intelligence-enrichment', selected],
    queryFn: () => apiHelpers.post<IntelligenceRecord>('/intelligence/enrich', { cve_id: selected }),
    enabled: Boolean(selected),
    retry: false,
  })

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    const value = cve.trim().toUpperCase()
    if (/^CVE-\d{4}-\d{4,}$/.test(value)) setSelected(value)
  }
  const providers = providersQuery.data?.providers ?? []
  const record = enrichQuery.data

  return (
    <section className="aegis-surface p-5">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div className="aegis-kicker flex items-center gap-2 text-primary"><Sparkles className="h-3.5 w-3.5" />Security intelligence fabric</div>
          <h2 className="aegis-title mt-1">Multi-source vulnerability intelligence</h2>
          <p className="aegis-subtitle mt-1 max-w-2xl">Live enrichment from NVD, OSV, CISA KEV and EPSS with normalized severity, exploit context and evidence lineage.</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Activity className="h-3.5 w-3.5" />
          {providersQuery.isLoading ? 'Checking providers…' : `${providers.filter((p) => p.status === 'configured').length}/${providers.length} providers configured`}
        </div>
      </div>

      <form onSubmit={submit} className="mt-4 flex flex-col gap-2 sm:flex-row">
        <input value={cve} onChange={(e) => setCve(e.target.value)} placeholder="Enter CVE, e.g. CVE-2024-3094" aria-label="CVE identifier" className="aegis-input min-w-0 flex-1 font-mono uppercase" />
        <button type="submit" disabled={!/^CVE-\d{4}-\d{4,}$/.test(cve.trim().toUpperCase()) || enrichQuery.isFetching} className="aegis-button aegis-button-primary disabled:cursor-not-allowed disabled:opacity-50">
          {enrichQuery.isFetching ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldAlert className="h-4 w-4" />}Enrich vulnerability
        </button>
      </form>

      <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        {providers.map((provider) => <div key={provider.id} className="flex items-center justify-between rounded-xl border bg-muted/20 px-3 py-2.5"><span className="flex items-center gap-2 text-xs font-medium"><Database className="h-3.5 w-3.5 text-muted-foreground" />{provider.id}</span><span className="rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase">{provider.status}</span></div>)}
      </div>

      {enrichQuery.isError && <div className="mt-4 rounded-xl border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">Intelligence enrichment failed. The provider layer may be unavailable or the CVE may not exist.</div>}
      {record && <div className="mt-4 rounded-2xl border bg-background/50 p-4">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div><div className="font-mono text-sm font-bold">{record.cve_id}</div><div className="mt-1 text-xs text-muted-foreground">{record.matched_assets.length ? `${record.matched_assets.length} correlated asset(s)` : 'No supplied asset matched'}</div></div>
          <div className="grid grid-cols-3 gap-2 text-center">
            <Metric label="CVSS" value={record.cvss == null ? '—' : record.cvss.toFixed(1)} />
            <Metric label="EPSS" value={record.epss == null ? '—' : `${(record.epss * 100).toFixed(1)}%`} />
            <Metric label="Risk" value={`${record.risk_score.toFixed(0)}/100`} />
          </div>
          <div className="flex flex-wrap items-center gap-2 text-[10px] font-semibold uppercase"><span className="rounded-full bg-muted px-2 py-1">{record.severity}</span>{record.kev && <span className="rounded-full bg-destructive/10 px-2 py-1 text-destructive">CISA KEV</span>}<span className="rounded-full border px-2 py-1">{Math.round(record.confidence * 100)}% confidence</span><span className="rounded-full border px-2 py-1">cache {record.cache}</span></div>
        </div>
        <div className="mt-4 flex flex-wrap gap-2 border-t pt-3">{record.evidence.map((item, index) => item.url ? <a key={`${item.source}-${index}`} href={item.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded-lg border px-2.5 py-1.5 text-[11px] hover:bg-accent">{item.source}<ExternalLink className="h-3 w-3" /></a> : <span key={`${item.source}-${index}`} className="rounded-lg border px-2.5 py-1.5 text-[11px]">{item.source}</span>)}</div>
      </div>}
    </section>
  )
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="rounded-xl border bg-muted/20 px-3 py-2"><div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div><div className="mt-1 text-sm font-bold">{value}</div></div>
}
