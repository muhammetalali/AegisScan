import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { CISOExecutiveView, type ExecutiveSecurityModel } from '@/components/security/CISOExecutiveView'

export const CISOExecutivePage = () => {
  const query = useQuery({ queryKey: ['ciso-executive'], queryFn: async () => { const [summary, risk] = await Promise.all([apiHelpers.get<any>('/dashboard/summary'), apiHelpers.get<any>('/dashboard/risk-distribution')]); return { summary, risk } } })
  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading executive posture…</div>
  if (query.error || !query.data) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Executive posture unavailable</h1><p className="mt-2 text-sm text-muted-foreground">The CISO view needs live dashboard data. No simulated executive metrics are shown when the API is unavailable.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>
  const { summary, risk } = query.data
  const model: ExecutiveSecurityModel = { securityScore: Number(summary?.security_score ?? summary?.score ?? 0), scoreDelta: Number(summary?.score_delta ?? 0), critical: Number(risk?.critical ?? 0), high: Number(risk?.high ?? 0), remediationRate: Number(summary?.remediation_rate ?? 0), controlCoverage: Number(summary?.control_coverage ?? 0), validationCoverage: Number(summary?.validation_coverage ?? 0), riskExposure: Number(summary?.risk_exposure ?? 0), openExceptions: Number(summary?.open_exceptions ?? 0) }
  return <CISOExecutiveView model={model} />
}
