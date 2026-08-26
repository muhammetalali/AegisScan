import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { RefreshCw, ShieldCheck } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'

export const Compliance = () => {
  const query = useQuery({ queryKey: ['compliance-overview'], queryFn: async () => {
    const vals = await apiHelpers.get<any>('/validations')
    const validations = Array.isArray(vals) ? vals : vals?.items ?? vals?.results ?? []
    const id = validations[0]?.id
    if (!id) return []
    const response = await apiHelpers.get<any>(`/validations/${id}/compliance`)
    return Array.isArray(response) ? response : response?.items ?? response?.results ?? []
  } })

  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading compliance…</div>
  if (query.error) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><ShieldCheck className="mx-auto h-8 w-8 text-amber-500" /><h1 className="mt-3 text-lg font-bold">Compliance unavailable</h1><p className="mt-2 text-sm text-muted-foreground">The live compliance data could not be retrieved. No simulated controls are shown.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>

  const items = query.data ?? []
  const pass = items.filter((item: any) => item.status === 'pass').length
  const fail = items.filter((item: any) => item.status === 'fail').length
  const partial = items.filter((item: any) => item.status === 'partial').length

  return <div className="space-y-5"><header className="flex flex-wrap items-end justify-between gap-3"><div><h1 className="flex items-center gap-2 text-2xl font-bold"><ShieldCheck className="h-6 w-6 text-primary" /> Compliance</h1><p className="text-sm text-muted-foreground">Live control coverage with finding, evidence, validation, and executive context.</p></div><Link to="/compliance/intelligence" className="rounded-lg bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground">Open Intelligence View</Link></header><div className="grid gap-3 md:grid-cols-4"><Metric label="Passed" value={pass} tone="success" /><Metric label="Failed" value={fail} tone="danger" /><Metric label="Partial" value={partial} tone="warning" /><Metric label="Controls" value={items.length} /></div><div className="overflow-hidden rounded-2xl border bg-card"><table className="w-full text-sm"><thead><tr className="border-b bg-muted/30 text-xs text-muted-foreground"><th className="px-4 py-3 text-start">Framework</th><th className="px-4 py-3 text-start">Control</th><th className="px-4 py-3 text-start">Status</th><th className="px-4 py-3 text-start">Findings</th><th className="px-4 py-3 text-start">Evidence</th></tr></thead><tbody>{items.map((item: any, index: number) => <tr key={item.id ?? index} className="border-b last:border-b-0 hover:bg-muted/20"><td className="px-4 py-3 font-mono text-xs">{item.framework ?? '—'}</td><td className="px-4 py-3 font-medium">{item.control ?? item.name ?? 'Unnamed control'}</td><td className="px-4 py-3"><span className={cn('rounded-md border px-2 py-0.5 text-xs capitalize', item.status === 'pass' && 'border-emerald-500/30 text-emerald-600', item.status === 'fail' && 'border-destructive/30 text-destructive', item.status === 'partial' && 'border-amber-500/30 text-amber-600')}>{String(item.status ?? 'not assessed').replace('_', ' ')}</span></td><td className="px-4 py-3 text-xs">{item.finding_count ?? item.findings_count ?? 0}</td><td className="px-4 py-3 text-xs text-muted-foreground">{item.evidence_count ?? 0}</td></tr>)}</tbody></table>{!items.length && <div className="p-10 text-center text-sm text-muted-foreground">No compliance controls have been assessed yet.</div>}</div></div>
}
function Metric({ label, value, tone }: { label: string; value: number; tone?: 'success' | 'danger' | 'warning' }) { return <div className={cn('rounded-xl border bg-card p-4', tone === 'success' && 'border-emerald-500/20', tone === 'danger' && 'border-destructive/20', tone === 'warning' && 'border-amber-500/20')}><div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div><div className="mt-1 text-2xl font-black">{value}</div></div> }
