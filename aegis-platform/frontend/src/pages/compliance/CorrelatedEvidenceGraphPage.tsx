import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { EvidenceGraph, type EvidenceGraphNode, type EvidenceGraphEdge } from '@/components/security/EvidenceGraph'
import type { CorrelationConflict } from '@/components/security/CorrelationConflictIntelligence'

export const CorrelatedEvidenceGraphPage = () => {
  const query = useQuery({ queryKey: ['correlated-evidence-graph'], queryFn: () => apiHelpers.get<unknown>('/assurance/correlations/conflicts') })
  const conflicts: CorrelationConflict[] = Array.isArray(query.data) ? query.data as CorrelationConflict[] : typeof query.data === 'object' && query.data !== null ? (((query.data as { items?: unknown[]; results?: unknown[] }).items ?? (query.data as { results?: unknown[] }).results ?? []) as CorrelationConflict[]) : []
  const nodes = useMemo<EvidenceGraphNode[]>(() => conflicts.flatMap((conflict) => [
    { id: `finding:${conflict.finding_id}`, label: conflict.finding_id, type: 'finding', status: 'unverified', conflictCount: conflict.validations.length },
    ...conflict.validations.map((validation) => ({ id: `validation:${validation.id}`, label: validation.engine || validation.id, type: 'validation' as const, status: validation.finding_present == null ? 'unverified' as const : validation.finding_present ? 'failed' as const : 'verified' as const, conflictCount: validation.finding_present == null ? 0 : 1, meta: validation.evidence_id ? `Evidence ${validation.evidence_id}` : 'No linked evidence' })),
  ]), [conflicts])
  const edges = useMemo<EvidenceGraphEdge[]>(() => conflicts.flatMap((conflict) => conflict.validations.map((validation) => ({ from: `finding:${conflict.finding_id}`, to: `validation:${validation.id}`, label: `${validation.engine || 'validation'} observation` }))), [conflicts])
  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading evidence intelligence…</div>
  if (query.error) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Evidence intelligence unavailable</h1><p className="mt-2 text-sm text-muted-foreground">The evidence graph could not retrieve live correlation signals.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>
  return <div className="space-y-5"><header><div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Assurance evidence</div><h1 className="mt-1 text-2xl font-black tracking-tight">Correlated Evidence Graph</h1><p className="mt-1 text-sm text-muted-foreground">Live correlation signals mapped directly onto findings and validation sources.</p></header><EvidenceGraph nodes={nodes} edges={edges} /></div>
}
