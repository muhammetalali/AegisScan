import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw, ShieldCheck } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { SecurityAssuranceCommandCenter, type AssuranceCommandItem } from '@/components/security/SecurityAssuranceCommandCenter'

function normalizeStatus(value: unknown): AssuranceCommandItem['status'] {
  return value === 'pass' || value === 'fail' || value === 'partial' ? value : 'not_assessed'
}

export const SecurityAssuranceCommandCenterPage = () => {
  const query = useQuery({
    queryKey: ['security-assurance-command-center'],
    queryFn: async () => {
      const validationsResponse = await apiHelpers.get<any>('/validations')
      const validations = Array.isArray(validationsResponse) ? validationsResponse : validationsResponse?.items ?? validationsResponse?.results ?? []
      const validationId = validations[0]?.id
      if (!validationId) return [] as AssuranceCommandItem[]
      const response = await apiHelpers.get<any>(`/validations/${validationId}/compliance`)
      const controls = Array.isArray(response) ? response : response?.items ?? response?.results ?? []
      return controls.map((item: any, index: number) => ({
        id: String(item.id ?? `${item.framework ?? 'framework'}-${item.control ?? index}`),
        control: String(item.control ?? item.name ?? 'Unnamed control'),
        framework: String(item.framework ?? 'Unknown framework'),
        status: normalizeStatus(item.status),
        findings: Number(item.finding_count ?? item.findings_count ?? 0),
        evidence: Number(item.evidence_count ?? 0),
        validations: Number(item.validation_count ?? 0),
        impact: Number(item.impact ?? item.executive_impact ?? 0),
        risk: Number(item.risk ?? item.risk_score ?? 0),
        verified: Boolean(item.verified ?? item.evidence_verified ?? false),
      })) as AssuranceCommandItem[]
    },
  })

  const data = useMemo(() => query.data ?? [], [query.data])

  return <div className="space-y-5">
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold"><ShieldCheck className="h-6 w-6 text-primary" /> Security Assurance</h1>
        <p className="mt-1 text-sm text-muted-foreground">Control → Finding → Evidence → Validation → Executive impact.</p>
      </div>
      {query.error && <button type="button" onClick={() => query.refetch()} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button>}
    </div>
    {query.isLoading ? <div className="rounded-2xl border bg-card p-10 text-center text-sm text-muted-foreground">Loading assurance intelligence…</div> : query.error ? <div className="rounded-2xl border bg-card p-10 text-center"><p className="font-semibold">Assurance data unavailable</p><p className="mt-1 text-xs text-muted-foreground">No simulated control state is displayed while live validation data is unavailable.</p></div> : <SecurityAssuranceCommandCenter items={data} />}
  </div>
}
