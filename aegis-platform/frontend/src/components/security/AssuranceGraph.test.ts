import { describe, expect, it } from 'vitest'
import { graphFromCorrelationPayload, graphMetrics, neighbors } from './AssuranceGraph'

describe('live assurance graph contract', () => {
  const live = {
    nodes: [
      { id: 'validation:1', kind: 'validation', label: 'Lab check', status: 'completed', risk: 30, confidence: 84, conflicts: 0, sources: 1, validationId: '1' },
      { id: 'engine:nmap', kind: 'engine', label: 'nmap', confidence: 90, risk: 0 },
      { id: 'finding:1', kind: 'finding', label: 'Exposed port', status: 'open', confidence: 80, risk: 20 },
    ],
    edges: [
      { source: 'validation:1', target: 'engine:nmap', relation: 'validated-by' },
      { source: 'finding:1', target: 'engine:nmap', relation: 'detected' },
    ],
    intelligence: { topPriorityNodes: [], attackPriorityPaths: [] },
  }

  it('adapts the live kind/source/target schema to graph rendering fields', () => {
    const graph = graphFromCorrelationPayload(live)
    expect(graph.nodes).toHaveLength(3)
    expect(graph.edges).toHaveLength(2)
    expect(graph.nodes[1].type).toBe('service')
    expect(graph.nodes[0].metadata?.validationId).toBe('1')
    expect(graph.edges[0]).toMatchObject({ from: 'validation:1', to: 'engine:nmap', type: 'validated-by' })
    expect(graph.edges[1].type).toBe('related-to')
    expect(graphMetrics(graph)).toMatchObject({ nodes: 3, edges: 2 })
    expect(neighbors(graph, 'validation:1')[0].id).toBe('engine:nmap')
  })

  it('does not crash or invent connections for malformed or absent records', () => {
    const graph = graphFromCorrelationPayload({ nodes: [{ id: 'a', kind: 'unknown', label: 'A' }], edges: [{ source: 'a', target: 'nonexistent', relation: 'test' }] })
    expect(graph.nodes[0].type).toBe('data')
    expect(graph.edges).toHaveLength(0)
    expect(graphMetrics(graph).nodes).toBe(1)
    expect(graphFromCorrelationPayload({ items: [] })).toMatchObject({ nodes: [], edges: [] })
  })
})
