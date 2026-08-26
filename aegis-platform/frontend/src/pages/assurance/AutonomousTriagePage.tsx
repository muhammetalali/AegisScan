import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { AutonomousTriagePanel, type TriagePayload } from '@/components/security/AutonomousTriagePanel'

export const AutonomousTriagePage = () => {
  const query = useQuery({ queryKey: ['autonomous-triage'], queryFn: () => apiHelpers.get<TriagePayload>('/assurance/triage') })
  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading autonomous triage…</div>
  if (query.error || !query.data) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Autonomous triage unavailable</h1><p className="mt-2 text-sm text-muted-foreground">Live assurance intelligence could not be retrieved.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>
  return <div className="space-y-5"><header><div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Security decision intelligence</div><h1 className="mt-1 text-2xl font-black tracking-tight">Autonomous Security Triage</h1><p className="mt-1 max-w-3xl text-sm text-muted-foreground">Prioritize investigations using graph risk, evidence strength, connectivity, and cross-source conflict signals.</p></header><AutonomousTriagePanel triage={query.data} onInvestigate={(item) => { const validationMatch = item.nodeId.match(/^finding:([^:]+):/) || item.nodeId.match(/^validation:([^:]+)$/); const validationId = validationMatch?.[1]; if (validationId) window.location.assign(`/validations/${validationId}/results`); else window.location.assign('/assurance/graph') }} /></div>
}
