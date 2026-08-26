import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { EvidenceGraph, type EvidenceGraphNode } from '@/components/security/EvidenceGraph'
import type { CorrelationConflict } from '@/components/security/CorrelationConflictIntelligence'

export const CorrelatedEvidenceGraphPage = () => {
  const query = useQuery({ queryKey: ['correlated-evidence-graph'], queryFn: () => apiHelpers.get<any>('/assurance/correlations/conflicts') })
  const conflicts: CorrelationConflict[] = Array.isArray(query.data) ? query.data : query.data?.items ?? query.data?.results ?? []
  const nodes = useMemo<EvidenceGraphNode[]>(() => conflicts.flatMap((conflict) => [
    { id: `finding:${conflict.entityId}`, label: conflict.entityLabel, type: 'finding', status: 'unverified', conflictCount: conflict.signals.length, confidence: conflict.confidenceAfter },
    ...conflict.signals.map((signal) => ({ id: `evidence:${signal.id}`, label: signal.source, type: 'evidence' as const, status: 'unverified' as const, conflictCount: 1, confidence: signal.confidence, meta: `${signal.claim}: ${signal.value}` })),
  ]), [conflicts])
  const edges = useMemo(() => conflicts.flatMap((conflict) => conflict.signals.map((signal) => ({ from: `finding:${conflict.entityId}`, to: `evidence:${signal.id}`, label: `${signal.source} signal` }))), [conflicts])
  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading evidence intelligence…</div>
  if (query.error) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Evidence intelligence unavailable</h1><p className="mt-2 text-sm text-muted-foreground">The evidence graph could not retrieve live correlation signals.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>
  return <div className="space-y-5"><header><div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Assurance evidence</div><h1 className="mt-1 text-2xl font-black tracking-tight">Correlated Evidence Graph</h1><p className="mt-1 text-sm text-muted-foreground">Live correlation signals mapped directly onto findings and evidence sources.</p></header><EvidenceGraph nodes={nodes} edges={edges} /></div>
}
