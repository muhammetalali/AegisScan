import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Bug, Search, Filter, Tag, MoreHorizontal, Eye, Check, Clock, Shield, AlertCircle } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'
import { useLanguageStore } from '@/stores/languageStore'

type Finding = {
  id: string
  title: string
  description?: string
  severity: string
  status: string
  confidence?: number | null
  cvss_score?: number | null
  risk_score?: number | null
  category?: string | null
  cwe?: string | null
  asset?: string | null
  asset_name?: string | null
  validation_id?: string | null
  source_engine?: string | null
}

const severityTone: Record<string, string> = {
  critical: 'border-red-500/25 bg-red-500/10 text-red-700 dark:text-red-300',
  high: 'border-orange-500/25 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  medium: 'border-amber-500/25 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  low: 'border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  informational: 'border-slate-500/25 bg-slate-500/10 text-slate-700 dark:text-slate-300',
}
const statuses = ['', 'open', 'confirmed', 'in_progress', 'resolved', 'accepted_risk', 'false_positive']
const severityOrder: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 }

export const Vulnerabilities = () => {
  const t = useLanguageStore(s => s.t)
  const [sev, setSev] = useState('')
  const [status, setStatus] = useState('')
  const [q, setQ] = useState('')
  const [sort, setSort] = useState<'severity' | 'confidence'>('severity')

  const query = useQuery<Finding[]>({
    queryKey: ['findings-center', sev, status, q],
    queryFn: () => {
      const params = new URLSearchParams({ limit: '200', offset: '0' })
      if (sev) params.set('severity', sev)
      if (status) params.set('status', status)
      if (q.trim()) params.set('search', q.trim())
      return apiHelpers.get<Finding[]>(`/vulnerabilities/?${params.toString()}`)
    },
  })

  const items = [...(query.data ?? [])].sort((a, b) => {
    if (sort === 'confidence') return (b.confidence ?? -1) - (a.confidence ?? -1)
    return (severityOrder[b.severity?.toLowerCase()] ?? 0) - (severityOrder[a.severity?.toLowerCase()] ?? 0)
  })

  return (
    <div className="space-y-5 pb-10">
      <section className="enterprise-card rounded-3xl p-5 md:p-7">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div><div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.16em] text-primary"><Bug className="h-4 w-4" /> {t('Findings')}</div><h1 className="mt-2 text-3xl font-semibold tracking-tight">Findings Center</h1><p className="mt-1 text-sm text-muted-foreground">{t('Search, sort, inspect evidence and launch finding-linked validation from real API data.')}</p></div>
          <Link to="/validations/new" className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground"><Check className="h-4 w-4" /> {t('New Validation')}</Link>
        </div>
      </section>

      <section className="enterprise-card rounded-2xl p-4 md:p-5">
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex flex-wrap gap-1.5">{['', 'critical', 'high', 'medium', 'low', 'informational'].map(item => <button key={item} type="button" onClick={() => setSev(item)} className={cn('rounded-full border px-3 py-1.5 text-xs capitalize', sev === item ? 'border-primary bg-primary text-primary-foreground' : 'bg-card hover:bg-accent')}>{item || 'All severity'}</button>)}</div>
          <div className="h-6 w-px bg-border mx-1" />
          <div className="flex flex-wrap gap-1.5">{statuses.map(item => <button key={item} type="button" onClick={() => setStatus(item)} className={cn('rounded-full border px-3 py-1.5 text-xs capitalize', status === item ? 'border-primary bg-primary text-primary-foreground' : 'bg-card hover:bg-accent')}>{item || 'Any status'}</button>)}</div>
          <select value={sort} onChange={e => setSort(e.target.value as 'severity' | 'confidence')} className="ms-auto rounded-xl border bg-background px-3 py-2 text-xs"><option value="severity">Sort: Severity</option><option value="confidence">Sort: Confidence</option></select>
        </div>
        <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative w-full max-w-xl"><Search className="absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><input value={q} onChange={e => setQ(e.target.value)} placeholder={t('Search findings, assets…')} className="h-11 w-full rounded-xl border bg-background ps-9 pe-3 text-sm outline-none focus:ring-2 focus:ring-primary/20" /></div>
          {!query.isLoading && !query.isError && <span className="text-xs text-muted-foreground">{items.length} findings returned by API</span>}
        </div>
      </section>

      {query.isLoading && <div className="enterprise-card rounded-2xl p-12 text-center text-sm text-muted-foreground">{t('Loading...')}</div>}
      {query.isError && <div className="enterprise-card rounded-2xl p-12 text-center"><AlertCircle className="mx-auto h-8 w-8 text-destructive" /><h2 className="mt-3 font-semibold">{t('Unable to load findings')}</h2><p className="mt-1 text-sm text-muted-foreground">The vulnerabilities API returned an error. No local or demo fallback is used.</p><button type="button" onClick={() => query.refetch()} className="mt-4 rounded-xl border px-4 py-2 text-sm font-medium">{t('Retry')}</button></div>}

      {!query.isLoading && !query.isError && <section className="enterprise-card overflow-hidden rounded-2xl"><div className="overflow-x-auto"><table className="w-full min-w-[980px] text-sm"><thead><tr className="border-b bg-muted/20 text-start text-xs text-muted-foreground"><th className="px-4 py-3">Severity</th><th className="px-4 py-3">Finding</th><th className="px-4 py-3">Asset</th><th className="px-4 py-3">Engine</th><th className="px-4 py-3">Validation</th><th className="px-4 py-3">Confidence</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Actions</th></tr></thead><tbody>
        {items.length === 0 ? <tr><td colSpan={8} className="px-6 py-16 text-center"><Bug className="mx-auto h-7 w-7 text-muted-foreground" /><div className="mt-3 font-medium">{t('No findings')}</div><div className="mt-1 text-xs text-muted-foreground">{t('Run a real scan or validation to populate the findings registry.')}</div></td></tr> : items.map(f => {
          const tone = severityTone[f.severity?.toLowerCase()] ?? severityTone.informational
          return <tr key={f.id} className="border-b last:border-0 transition hover:bg-muted/20"><td className="px-4 py-3"><span className={cn('inline-flex rounded-full border px-2 py-1 text-[11px] font-semibold capitalize', tone)}>{f.severity}</span></td><td className="px-4 py-3"><Link to={`/vulnerabilities/${f.id}`} className="font-semibold hover:text-primary">{f.title}</Link><div className="mt-1 flex flex-wrap items-center gap-1 text-[11px] text-muted-foreground"><Tag className="h-3 w-3" />{f.category || 'Security finding'}{f.cwe ? ` • ${f.cwe}` : ''}{f.cvss_score != null ? ` • CVSS ${f.cvss_score}` : ''}</div></td><td className="px-4 py-3 font-mono text-xs">{f.asset || f.asset_name || 'Unavailable'}</td><td className="px-4 py-3 text-xs">{f.source_engine || 'Not reported'}</td><td className="px-4 py-3 font-mono text-xs">{f.validation_id ? <Link to={`/validations/${f.validation_id}/results`} className="text-primary hover:underline">{f.validation_id}</Link> : <span className="text-muted-foreground">Not reported</span>}</td><td className="px-4 py-3">{f.confidence == null ? 'Not reported' : `${f.confidence}%`}</td><td className="px-4 py-3"><span className="rounded-lg border bg-muted/30 px-2 py-1 text-[11px] capitalize">{f.status || 'Not reported'}</span></td><td className="px-4 py-3"><div className="flex gap-1"><Link to={`/vulnerabilities/${f.id}`} className="rounded-lg p-2 hover:bg-accent" title="View Evidence"><Eye className="h-4 w-4" /></Link><Link to={`/vulnerabilities/${f.id}`} className="rounded-lg p-2 hover:bg-accent" title="Assign"><Shield className="h-4 w-4" /></Link><Link to={`/validations/new?finding_id=${encodeURIComponent(f.id)}`} className="rounded-lg p-2 text-primary hover:bg-primary/10" title="Validate"><Check className="h-4 w-4" /></Link><Link to={`/vulnerabilities/${f.id}`} className="rounded-lg p-2 hover:bg-accent" title="More"><MoreHorizontal className="h-4 w-4" /></Link></div></td></tr>
        })}</tbody></table></div><div className="flex flex-wrap gap-3 border-t bg-muted/10 px-4 py-3 text-xs text-muted-foreground"><span className="inline-flex items-center gap-1"><Clock className="h-3 w-3" />Status: Open → Confirmed → In Progress → Resolved → Accepted Risk → False Positive</span><span className="ms-auto inline-flex items-center gap-1"><Filter className="h-3 w-3" />Actions: Assign • Add Note • Change Status • Validate • Create Ticket • View Evidence</span></div></section>}
    </div>
  )
}
