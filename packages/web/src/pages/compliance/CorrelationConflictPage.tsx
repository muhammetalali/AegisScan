import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { CorrelationConflictIntelligence, type CorrelationConflict } from '@/components/security/CorrelationConflictIntelligence'

export const CorrelationConflictPage = () => {
  const query = useQuery({ queryKey: ['correlation-conflicts'], queryFn: async () => apiHelpers.get<any>('/assurance/correlations/conflicts') })
  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading correlation intelligence…</div>
  if (query.error) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Correlation intelligence unavailable</h1><p className="mt-2 text-sm text-muted-foreground">Live conflict signals could not be retrieved.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>
  const conflicts: CorrelationConflict[] = Array.isArray(query.data) ? query.data : query.data?.items ?? query.data?.results ?? []
  return <div className="space-y-5"><header><div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Continuous assurance</div><h1 className="mt-1 text-2xl font-black tracking-tight">Correlation & Conflict Intelligence</h1><p className="mt-1 text-sm text-muted-foreground">Investigate disagreement across scanners, evidence, validation, compliance, and intelligence sources.</p></header><CorrelationConflictIntelligence conflicts={conflicts} /></div>
}
