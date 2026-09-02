import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Database, FileText, RefreshCw, Search, ShieldCheck } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { cn } from '@/utils/cn'
import { useLanguageStore } from '@/stores/languageStore'

type EvidenceItem = {
  id: string
  project_id?: string | null
  scan_id?: string | null
  asset_id?: string | null
  finding_id?: string | null
  source: string
  evidence_type: string
  target?: string | null
  sha256: string
  collected_at: string
  metadata: Record<string, unknown>
}

export const Evidence = () => {
  const t = useLanguageStore(s => s.t)
  const [q, setQ] = useState('')
  const [source, setSource] = useState('')
  const [type, setType] = useState('')
  const query = useQuery<EvidenceItem[]>({
    queryKey: ['evidence-registry', source, type],
    queryFn: () => apiHelpers.get<EvidenceItem[]>('/evidence/', { params: { source: source || undefined, evidence_type: type || undefined, limit: 500 } }),
  })

  const items = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (!needle) return query.data ?? []
    return (query.data ?? []).filter(item => [item.id, item.source, item.evidence_type, item.target, item.finding_id, item.scan_id].some(value => String(value ?? '').toLowerCase().includes(needle)))
  }, [query.data, q])

  const sourceOptions = useMemo(() => Array.from(new Set((query.data ?? []).map(item => item.source))).sort(), [query.data])
  const typeOptions = useMemo(() => Array.from(new Set((query.data ?? []).map(item => item.evidence_type))).sort(), [query.data])

  return (
    <div className="space-y-6 pb-10">
      <section className="enterprise-card rounded-3xl p-6 md:p-8">
        <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <div>
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.16em] text-primary"><ShieldCheck className="h-4 w-4" />{t('Evidence')}</div>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight">{t('Evidence registry')}</h1>
            <p className="mt-2 max-w-3xl text-sm leading-7 text-muted-foreground">{t('Every record below is read from persisted Evidence and includes provenance metadata and the SHA-256 of the raw output.')}</p>
          </div>
          <button type="button" onClick={() => query.refetch()} disabled={query.isFetching} className="inline-flex items-center gap-2 rounded-xl border bg-card px-4 py-2.5 text-sm font-semibold hover:bg-accent"><RefreshCw className={cn('h-4 w-4', query.isFetching && 'animate-spin')} />{t('Refresh')}</button>
        </div>
      </section>

      <section className="enterprise-card rounded-2xl p-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
          <div className="relative flex-1 max-w-xl"><Search className="absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"/><input value={q} onChange={e => setQ(e.target.value)} placeholder={t('Search evidence, source, target or hash…')} className="h-11 w-full rounded-xl border bg-background ps-9 pe-3 text-sm outline-none focus:ring-2 focus:ring-primary/20"/></div>
          <select value={source} onChange={e => setSource(e.target.value)} className="h-11 rounded-xl border bg-background px-3 text-sm"><option value="">{t('All sources')}</option>{sourceOptions.map(value => <option key={value} value={value}>{value}</option>)}</select>
          <select value={type} onChange={e => setType(e.target.value)} className="h-11 rounded-xl border bg-background px-3 text-sm"><option value="">{t('All types')}</option>{typeOptions.map(value => <option key={value} value={value}>{value}</option>)}</select>
          {!query.isLoading && !query.isError && <span className="text-xs text-muted-foreground">{items.length} {t('records')}</span>}
        </div>
      </section>

      {query.isLoading && <div className="enterprise-card rounded-2xl p-12 text-center text-sm text-muted-foreground">{t('Loading...')}</div>}
      {query.isError && <div className="enterprise-card rounded-2xl p-12 text-center"><Database className="mx-auto h-8 w-8 text-destructive"/><h2 className="mt-3 font-semibold">{t('Unable to load evidence')}</h2><p className="mt-1 text-sm text-muted-foreground">{t('The evidence API returned an error. No synthetic evidence records are displayed.')}</p><button type="button" onClick={() => query.refetch()} className="mt-4 rounded-xl border px-4 py-2 text-sm font-medium">{t('Retry')}</button></div>}

      {!query.isLoading && !query.isError && (
        <section className="enterprise-card overflow-hidden rounded-2xl">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1120px] text-sm">
              <thead><tr className="border-b bg-muted/20 text-xs text-muted-foreground"><th className="px-4 py-3 text-start">{t('Source')}</th><th className="px-4 py-3 text-start">{t('Type')}</th><th className="px-4 py-3 text-start">{t('Target')}</th><th className="px-4 py-3 text-start">{t('Finding')}</th><th className="px-4 py-3 text-start">{t('Scan')}</th><th className="px-4 py-3 text-start">SHA-256</th><th className="px-4 py-3 text-start">{t('Collected')}</th><th className="px-4 py-3 text-start">{t('Metadata')}</th></tr></thead>
              <tbody>{items.length === 0 ? <tr><td colSpan={8} className="px-6 py-16 text-center"><FileText className="mx-auto h-7 w-7 text-muted-foreground"/><div className="mt-3 font-medium">{t('No evidence available')}</div></td></tr> : items.map(item => <tr key={item.id} className="border-b last:border-0 hover:bg-muted/20"><td className="px-4 py-3 font-semibold">{item.source || t('Not reported')}</td><td className="px-4 py-3"><span className="rounded-full border bg-muted/30 px-2 py-1 text-[11px]">{item.evidence_type || t('Not reported')}</span></td><td className="px-4 py-3 max-w-[220px] truncate font-mono text-xs">{item.target || t('Not reported')}</td><td className="px-4 py-3 font-mono text-[11px]">{item.finding_id || t('Not linked')}</td><td className="px-4 py-3 font-mono text-[11px]">{item.scan_id || t('Not linked')}</td><td className="px-4 py-3 font-mono text-[11px] max-w-[260px] truncate" title={item.sha256}>{item.sha256}</td><td className="px-4 py-3 text-xs text-muted-foreground">{new Date(item.collected_at).toLocaleString()}</td><td className="px-4 py-3 text-xs text-muted-foreground">{Object.keys(item.metadata || {}).length} {t('fields')}</td></tr>)}</tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}
