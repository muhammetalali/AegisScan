import { useQuery } from '@tanstack/react-query'
import { RefreshCw, ShieldCheck } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { ComplianceIntelligence, type ComplianceIntelligenceItem } from '@/components/security/ComplianceIntelligence'

export const ComplianceIntelligencePage = () => {
  const query = useQuery({ queryKey: ['compliance-intelligence'], queryFn: async () => {
    const validationsResponse = await apiHelpers.get<any>('/validations')
    const validations = Array.isArray(validationsResponse) ? validationsResponse : validationsResponse?.items ?? validationsResponse?.results ?? []
    const validationId = validations[0]?.id
    if (!validationId) return [] as ComplianceIntelligenceItem[]
    const response = await apiHelpers.get<any>(`/validations/${validationId}/compliance`)
    const controls = Array.isArray(response) ? response : response?.items ?? response?.results ?? []
    return controls.map((item: any, index: number) => ({ id: String(item.id ?? `${item.framework ?? 'framework'}-${item.control ?? index}`), framework: String(item.framework ?? 'Unknown'), control: String(item.control ?? item.name ?? 'Unnamed control'), status: item.status === 'pass' || item.status === 'fail' || item.status === 'partial' ? item.status : 'not_assessed', findingCount: Number(item.finding_count ?? item.findings_count ?? 0), evidenceCount: Number(item.evidence_count ?? 0), validationCount: Number(item.validation_count ?? 1), impact: item.impact === undefined ? undefined : Number(item.impact) })) as ComplianceIntelligenceItem[]
  } })
  return <div className="space-y-5"><div><h1 className="flex items-center gap-2 text-2xl font-bold"><ShieldCheck className="h-6 w-6 text-primary" /> Compliance Intelligence</h1><p className="text-sm text-muted-foreground">Control → Finding → Evidence → Validation → Executive impact.</p></div>{query.isLoading ? <div className="rounded-2xl border bg-card p-10 text-center text-sm text-muted-foreground">Loading compliance intelligence…</div> : query.error ? <div className="rounded-2xl border bg-card p-10 text-center"><p className="text-sm font-semibold">Unable to load compliance data</p><p className="mt-1 text-xs text-muted-foreground">No simulated controls are shown while the API is unavailable.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div> : <ComplianceIntelligence items={query.data ?? []} />}</div>
}
