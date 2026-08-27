export type AssuranceNodeType = 'finding' | 'asset' | 'service' | 'endpoint' | 'evidence' | 'validation' | 'control' | 'threat' | 'data' | 'remediation'
export type AssuranceNodeStatus = 'open' | 'verified' | 'impacted' | 'unverified' | 'failed' | 'resolved' | 'unknown'
export type AssuranceEdgeType = 'affects' | 'depends-on' | 'detected-by' | 'supported-by' | 'validated-by' | 'maps-to' | 'threatens' | 'remediated-by' | 'related-to'

export type AssuranceNode = {
  id: string
  label: string
  type: AssuranceNodeType
  status?: AssuranceNodeStatus
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
  risk?: number
  confidence?: number
  conflictCount?: number
  sourceCount?: number
  metadata?: Record<string, string | number | boolean | null>
}

export type AssuranceEdge = {
  id: string
  from: string
  to: string
  type: AssuranceEdgeType
  confidence?: number
  conflictCount?: number
  metadata?: Record<string, string | number | boolean | null>
}

export type AssuranceGraph = {
  nodes: AssuranceNode[]
  edges: AssuranceEdge[]
  generatedAt?: string
  version?: string
}

export type AssuranceGraphMetrics = {
  nodes: number
  edges: number
  conflicts: number
  evidenceBacked: number
  averageConfidence: number
  criticalNodes: number
}

export function graphMetrics(graph: AssuranceGraph): AssuranceGraphMetrics {
  const validConfidence = graph.nodes.map((n) => n.confidence).filter((v): v is number => typeof v === 'number')
  return {
    nodes: graph.nodes.length,
    edges: graph.edges.length,
    conflicts: graph.nodes.reduce((sum, node) => sum + (node.conflictCount ?? 0), 0),
    evidenceBacked: graph.nodes.filter((node) => node.type === 'evidence' || node.status === 'verified').length,
    averageConfidence: validConfidence.length ? Math.round(validConfidence.reduce((a, b) => a + b, 0) / validConfidence.length) : 0,
    criticalNodes: graph.nodes.filter((node) => node.severity === 'critical').length,
  }
}

export function neighbors(graph: AssuranceGraph, nodeId: string): AssuranceNode[] {
  const ids = new Set<string>()
  for (const edge of graph.edges) {
    if (edge.from === nodeId) ids.add(edge.to)
    if (edge.to === nodeId) ids.add(edge.from)
  }
  return graph.nodes.filter((node) => ids.has(node.id))
}

export function graphFromCorrelationPayload(payload: any): AssuranceGraph {
  const conflicts = Array.isArray(payload?.items) ? payload.items : []
  const nodes = new Map<string, AssuranceNode>()
  const edges: AssuranceEdge[] = []
  for (const conflict of conflicts) {
    const entityId = String(conflict.entityId ?? conflict.id)
    nodes.set(entityId, {
      id: entityId,
      label: String(conflict.entityLabel ?? entityId),
      type: 'finding',
      status: 'impacted',
      risk: Number(conflict.impact ?? 0),
      confidence: Number(conflict.confidenceAfter ?? conflict.confidenceBefore ?? 0),
      conflictCount: 1,
      sourceCount: Array.isArray(conflict.signals) ? conflict.signals.length : 0,
    })
    for (const signal of Array.isArray(conflict.signals) ? conflict.signals : []) {
      const evidenceId = String(signal.evidenceId ?? `${entityId}:${signal.source}`)
      nodes.set(evidenceId, {
        id: evidenceId,
        label: String(signal.source ?? 'Signal'),
        type: 'evidence',
        status: 'unverified',
        confidence: Number(signal.confidence ?? 0),
        metadata: { claim: String(signal.claim ?? ''), value: String(signal.value ?? ''), observedAt: signal.observedAt ?? null },
      })
      edges.push({ id: `${entityId}->${evidenceId}`, from: entityId, to: evidenceId, type: 'supported-by', confidence: Number(signal.confidence ?? 0) })
    }
  }
  return { nodes: [...nodes.values()], edges, generatedAt: new Date().toISOString(), version: '1.0' }
}
