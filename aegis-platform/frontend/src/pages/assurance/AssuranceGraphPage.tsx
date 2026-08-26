import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { AssuranceGraphView } from '@/components/security/AssuranceGraphView'
import { graphFromCorrelationPayload, graphMetrics } from '@/components/security/AssuranceGraph'

function adaptAggregatorPayload(payload: any) {
  if (payload?.nodes && payload?.edges) {
    return {
      items: (payload.edges ?? []).map((edge: any) => ({
        id: `${edge.source}:${edge.target}:${edge.relation}`,
        entityId: edge.source,
        entityLabel: edge.relation,
        impact: Number(edge.risk ?? 0),
        signals: [],
        recommendedAction: edge.relation,
      })),
      graph: payload,
    }
  }
  return payload
}

export const AssuranceGraphPage = () => {
  const query = useQuery({ queryKey: ['assurance-graph'], queryFn: () => apiHelpers.get<any>('/assurance/graph') })
  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading assurance graph…</div>
  if (query.error) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Assurance graph unavailable</h1><p className="mt-2 text-sm text-muted-foreground">Live aggregated assurance data could not be retrieved.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>
  const graph = query.data?.nodes && query.data?.edges ? query.data : graphFromCorrelationPayload(adaptAggregatorPayload(query.data))
  const metrics = graphMetrics(graph)
  return <div className="space-y-5"><header><div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Assurance intelligence</div><h1 className="mt-1 text-2xl font-black tracking-tight">Unified Assurance Graph</h1><p className="mt-1 max-w-3xl text-sm text-muted-foreground">Graph-native view of findings, evidence, validations, engine signals, conflicts, and assurance relationships.</p></header><div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">{[['Nodes', metrics.nodes], ['Relations', metrics.edges], ['Conflicts', metrics.conflicts], ['Evidence-backed', metrics.evidenceBacked], ['Avg confidence', `${metrics.averageConfidence}%`], ['Critical', metrics.criticalNodes]].map(([label, value]) => <div key={String(label)} className="rounded-xl border bg-card p-4"><div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div><div className="mt-1 text-xl font-black">{value}</div></div>)}</div><AssuranceGraphView graph={graph} onInvestigate={(node) => { if (node.metadata?.validationId) window.location.assign(`/validations/${node.metadata.validationId}/results`) }} /></div>
}
