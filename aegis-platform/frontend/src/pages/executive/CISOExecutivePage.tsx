import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { CISOExecutiveView, type ExecutiveSecurityModel } from '@/components/security/CISOExecutiveView'
import { normalizeAssuranceModel } from '@/components/security/SecurityAssuranceModel'
import { ComplianceIntelligence, type ComplianceIntelligenceItem } from '@/components/security/ComplianceIntelligence'
import { AssuranceGraphView } from '@/components/security/AssuranceGraphView'
import type { AssuranceGraph } from '@/components/security/AssuranceGraph'

export const CISOExecutivePage = () => {
  const query = useQuery({ queryKey: ['ciso-executive'], queryFn: async () => {
    const [summary, risk, correlation, validationsResponse] = await Promise.all([
      apiHelpers.get<any>('/dashboard/summary'), apiHelpers.get<any>('/dashboard/risk-distribution'), apiHelpers.get<any>('/assurance/correlations/summary'), apiHelpers.get<any>('/validations'),
    ])
    const validations = Array.isArray(validationsResponse) ? validationsResponse : validationsResponse?.items ?? validationsResponse?.results ?? []
    const validationId = validations[0]?.id
    let compliance: ComplianceIntelligenceItem[] = []
    if (validationId) {
      const response = await apiHelpers.get<any>(`/validations/${validationId}/compliance`)
      const controls = Array.isArray(response) ? response : response?.items ?? response?.results ?? []
      compliance = controls.map((item: any, index: number) => ({ id: String(item.id ?? `${item.framework ?? 'framework'}-${item.control ?? index}`), framework: String(item.framework ?? 'Unknown'), control: String(item.control ?? item.name ?? 'Unnamed control'), status: ['pass', 'fail', 'partial'].includes(item.status) ? item.status : 'not_assessed', findingCount: Number(item.finding_count ?? item.findings_count ?? 0), evidenceCount: Number(item.evidence_count ?? 0), validationCount: Number(item.validation_count ?? 1), impact: item.impact === undefined ? undefined : Number(item.impact) })) as ComplianceIntelligenceItem[]
    }
    return { model: normalizeAssuranceModel(summary, risk), correlation, compliance, validationId: validationId ? String(validationId) : undefined }
  } })
  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading executive posture…</div>
  if (query.error || !query.data) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Executive posture unavailable</h1><p className="mt-2 text-sm text-muted-foreground">The CISO view needs live dashboard, assurance and compliance data. No simulated executive metrics are shown when the API is unavailable.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>

  const c = query.data.correlation ?? {}
  const model: ExecutiveSecurityModel = { ...query.data.model, assuranceConflicts: Number(c.conflicts ?? 0), assuranceConfidence: Number(c.confidence ?? 0) }
  const compliance = query.data.compliance
  const failed = compliance.filter((item) => item.status === 'fail').length
  const partial = compliance.filter((item) => item.status === 'partial').length
  const evidenceBacked = compliance.filter((item) => (item.evidenceCount ?? 0) > 0).length
  const correlationItems = Array.isArray(c.items) ? c.items : []
  const graph: AssuranceGraph = buildExecutiveGraph(model, compliance, query.data.validationId, correlationItems)

  return <div className="space-y-6">
    <CISOExecutiveView model={model} onOpenReports={() => window.location.assign('/reports')} onOpenConflicts={() => window.location.assign('/assurance/conflicts')} />
    <section className="mx-auto max-w-[1600px] px-6"><div className="mb-3 flex flex-wrap items-end justify-between gap-3"><div><div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Unified assurance control plane</div><h2 className="mt-1 text-xl font-black tracking-tight">Evidence → Risk → Governance → Outcome</h2><p className="mt-1 max-w-3xl text-xs text-muted-foreground">One traceable graph connecting the live executive model with correlation, compliance, evidence, validation and remediation signals.</p></div><div className="rounded-full border px-3 py-1 text-[10px] font-semibold">{graph.nodes.length} nodes · {graph.edges.length} relations</div></div><AssuranceGraphView graph={graph} onInvestigate={(node) => { if (node.type === 'finding' || node.type === 'evidence') window.location.assign('/compliance/correlated-evidence') }} /></section>
    <section className="mx-auto max-w-[1600px] px-6 pb-6"><div className="mb-3 flex flex-wrap items-end justify-between gap-3"><div><div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Governance evidence layer</div><h2 className="mt-1 text-xl font-black tracking-tight">Compliance impact chain</h2><p className="mt-1 text-xs text-muted-foreground">Control → Finding → Evidence → Validation → Executive impact, using the latest real validation.</p></div><div className="flex gap-2 text-[10px] font-semibold"><span className="rounded-full border px-2.5 py-1">{failed} failed</span><span className="rounded-full border px-2.5 py-1">{partial} partial</span><span className="rounded-full border px-2.5 py-1">{evidenceBacked} evidence-backed</span></div></div><ComplianceIntelligence items={compliance} /></section>
  </div>
}

function buildExecutiveGraph(model: ExecutiveSecurityModel, compliance: ComplianceIntelligenceItem[], validationId?: string, correlationItems: any[] = []): AssuranceGraph {
  const nodes: AssuranceGraph['nodes'] = []
  const edges: AssuranceGraph['edges'] = []
  const addNode = (node: AssuranceGraph['nodes'][number]) => nodes.push(node)
  const addEdge = (from: string, to: string, type: AssuranceGraph['edges'][number]['type'], confidence?: number, conflictCount?: number) => edges.push({ id: `${from}->${to}`, from, to, type, confidence, conflictCount })
  const validationNode = validationId ?? 'latest-validation'

  addNode({ id: validationNode, label: validationId ? `Validation ${validationId.slice(0, 8)}` : 'Latest validation', type: 'validation', status: 'verified', confidence: model.assuranceConfidence, sourceCount: compliance.reduce((n, item) => n + (item.evidenceCount ?? 0), 0) })
  addNode({ id: 'risk:exposure', label: 'Risk exposure', type: 'threat', status: model.critical > 0 ? 'impacted' : 'unknown', risk: model.riskExposure, severity: model.critical > 0 ? 'critical' : 'medium', confidence: model.assuranceConfidence, conflictCount: model.assuranceConflicts })
  addNode({ id: 'posture', label: 'Security posture', type: 'asset', status: model.scoreDelta >= 0 ? 'verified' : 'impacted', risk: model.riskExposure, confidence: model.assuranceConfidence })
  addNode({ id: 'remediation', label: 'Remediation outcome', type: 'remediation', status: model.remediationRate >= 80 ? 'resolved' : 'open', risk: model.remediationRate, confidence: model.validationCoverage })
  addNode({ id: 'executive', label: 'CISO executive impact', type: 'data', status: model.critical > 0 ? 'impacted' : 'unknown', confidence: model.assuranceConfidence, metadata: { securityScore: model.securityScore, controlCoverage: model.controlCoverage, validationCoverage: model.validationCoverage } })
  addEdge(validationNode, 'risk:exposure', 'validated-by', model.assuranceConfidence)
  addEdge('risk:exposure', 'posture', 'affects', model.assuranceConfidence, model.assuranceConflicts)
  addEdge('posture', 'remediation', 'remediated-by', model.validationCoverage)
  addEdge('remediation', 'executive', 'related-to', model.assuranceConfidence)
  addEdge('risk:exposure', 'executive', 'threatens', model.assuranceConfidence, model.assuranceConflicts)

  for (const item of compliance.slice(0, 12)) {
    const controlId = `control:${item.id}`
    addNode({ id: controlId, label: item.control, type: 'control', status: item.status === 'pass' ? 'verified' : item.status === 'fail' ? 'failed' : item.status === 'partial' ? 'impacted' : 'unknown', confidence: item.validationCount > 0 ? Math.min(100, item.validationCount * 25) : undefined, sourceCount: item.evidenceCount, metadata: { framework: item.framework, findings: item.findingCount, evidence: item.evidenceCount } })
    addEdge(validationNode, controlId, 'maps-to')
    addEdge(controlId, 'risk:exposure', item.status === 'fail' ? 'affects' : 'related-to')
    if (item.evidenceCount > 0) {
      const evidenceId = `evidence:${item.id}`
      addNode({ id: evidenceId, label: `${item.evidenceCount} evidence item${item.evidenceCount === 1 ? '' : 's'}`, type: 'evidence', status: 'verified', sourceCount: item.evidenceCount, confidence: Math.min(100, 60 + item.evidenceCount * 5) })
      addEdge(controlId, evidenceId, 'supported-by')
      addEdge(evidenceId, validationNode, 'validated-by')
    }
    if (item.findingCount > 0) {
      const findingId = `finding:${item.id}`
      addNode({ id: findingId, label: `${item.findingCount} finding${item.findingCount === 1 ? '' : 's'}`, type: 'finding', status: item.status === 'fail' ? 'open' : 'impacted', severity: item.status === 'fail' ? 'high' : 'medium', metadata: { control: item.control } })
      addEdge(findingId, controlId, 'maps-to')
      addEdge(findingId, 'risk:exposure', 'affects')
    }
  }

  for (const [index, item] of correlationItems.slice(0, 8).entries()) {
    const id = `correlation:${item.id ?? index}`
    const confidence = Number(item.confidenceAfter ?? item.confidenceBefore ?? 0)
    addNode({ id, label: String(item.entityLabel ?? item.entityId ?? `Correlation ${index + 1}`), type: 'finding', status: 'impacted', risk: Number(item.impact ?? 0), confidence, conflictCount: 1, sourceCount: Array.isArray(item.signals) ? item.signals.length : 0 })
    addEdge(id, 'risk:exposure', 'affects', confidence, 1)
    for (const [signalIndex, signal] of (Array.isArray(item.signals) ? item.signals : []).slice(0, 4).entries()) {
      const evidenceId = `correlation-evidence:${item.id ?? index}:${signal.evidenceId ?? signalIndex}`
      const signalConfidence = Number(signal.confidence ?? 0)
      addNode({ id: evidenceId, label: String(signal.source ?? 'Signal'), type: 'evidence', status: 'unverified', confidence: signalConfidence, metadata: { claim: String(signal.claim ?? ''), value: String(signal.value ?? '') } })
      addEdge(id, evidenceId, 'supported-by', signalConfidence)
    }
  }
  return { nodes, edges, generatedAt: new Date().toISOString(), version: '2.0' }
}
