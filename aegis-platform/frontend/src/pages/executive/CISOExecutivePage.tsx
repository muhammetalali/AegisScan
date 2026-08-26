import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { CISOExecutiveView, type ExecutiveSecurityModel } from '@/components/security/CISOExecutiveView'
import { normalizeAssuranceModel } from '@/components/security/SecurityAssuranceModel'

export const CISOExecutivePage = () => {
  const query = useQuery({ queryKey: ['ciso-executive'], queryFn: async () => {
    const [summary, risk, conflicts] = await Promise.all([
      apiHelpers.get<any>('/dashboard/summary'),
      apiHelpers.get<any>('/dashboard/risk-distribution'),
      apiHelpers.get<any>('/assurance/correlations/conflicts'),
    ])
    return { model: normalizeAssuranceModel(summary, risk), conflicts: Array.isArray(conflicts) ? conflicts : conflicts?.items ?? conflicts?.results ?? [] }
  } })
  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading executive posture…</div>
  if (query.error || !query.data) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Executive posture unavailable</h1><p className="mt-2 text-sm text-muted-foreground">The CISO view needs live dashboard and assurance data. No simulated executive metrics are shown when the API is unavailable.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>
  const model: ExecutiveSecurityModel = { ...query.data.model, assuranceConflicts: query.data.conflicts.length, assuranceConfidence: query.data.conflicts.length ? Math.max(0, 100 - Math.min(80, query.data.conflicts.length * 8)) : 100 }
  return <CISOExecutiveView model={model} onOpenReports={() => { window.location.assign('/reports') }} onOpenConflicts={() => { window.location.assign('/assurance/conflicts') }} />
}
