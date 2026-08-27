import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { CISOExecutiveView, type ExecutiveSecurityModel } from '@/components/security/CISOExecutiveView'
import { normalizeAssuranceModel } from '@/components/security/SecurityAssuranceModel'
import { ComplianceIntelligence, type ComplianceIntelligenceItem } from '@/components/security/ComplianceIntelligence'

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
    return { model: normalizeAssuranceModel(summary, risk), correlation, compliance }
  } })
  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading executive posture…</div>
  if (query.error || !query.data) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Executive posture unavailable</h1><p className="mt-2 text-sm text-muted-foreground">The CISO view needs live dashboard, assurance and compliance data. No simulated executive metrics are shown when the API is unavailable.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>
  const c = query.data.correlation ?? {}
  const model: ExecutiveSecurityModel = { ...query.data.model, assuranceConflicts: Number(c.conflicts ?? 0), assuranceConfidence: Number(c.confidence ?? 0) }
  const compliance = query.data.compliance
  const failed = compliance.filter((item) => item.status === 'fail').length
  const partial = compliance.filter((item) => item.status === 'partial').length
  const evidenceBacked = compliance.filter((item) => (item.evidenceCount ?? 0) > 0).length
  return <div className="space-y-6"><CISOExecutiveView model={model} onOpenReports={() => window.location.assign('/reports')} onOpenConflicts={() => window.location.assign('/assurance/conflicts')} /><section className="mx-auto max-w-[1600px] px-6 pb-6"><div className="mb-3 flex flex-wrap items-end justify-between gap-3"><div><div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Governance evidence layer</div><h2 className="mt-1 text-xl font-black tracking-tight">Compliance impact chain</h2><p className="mt-1 text-xs text-muted-foreground">Control → Finding → Evidence → Validation → Executive impact, using the latest real validation.</p></div><div className="flex gap-2 text-[10px] font-semibold"><span className="rounded-full border px-2.5 py-1">{failed} failed</span><span className="rounded-full border px-2.5 py-1">{partial} partial</span><span className="rounded-full border px-2.5 py-1">{evidenceBacked} evidence-backed</span></div></div><ComplianceIntelligence items={compliance} /></section></div>
}
