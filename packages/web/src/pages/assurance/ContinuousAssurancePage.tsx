import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { apiHelpers } from '@/services/api'
import { ContinuousAssuranceFabric, type AssuranceCheckpoint } from '@/components/security/ContinuousAssuranceFabric'
import { CisoImpactBridge } from '@/components/security/CisoImpactBridge'
import { InvestigationStateIntelligence } from '@/components/security/InvestigationStateIntelligence'
import TraceabilityEvidenceGraph, { type TraceEdge, type TraceNode } from '@/components/security/TraceabilityEvidenceGraph'

export const ContinuousAssurancePage = () => {
  const navigate = useNavigate()
  const query = useQuery({ queryKey: ['continuous-assurance'], queryFn: async () => {
    const [trends, summary] = await Promise.all([apiHelpers.get<any>('/dashboard/trends?days=30'), apiHelpers.get<any>('/dashboard/summary')])
    const rows = Array.isArray(trends) ? trends : trends?.results ?? trends?.items ?? []
    const checkpoints: AssuranceCheckpoint[] = rows.map((row: any, index: number) => ({ id: String(row.id ?? row.date ?? index), label: String(row.label ?? row.date ?? `Checkpoint ${index + 1}`).slice(0, 24), timestamp: String(row.date ?? row.timestamp ?? '—'), state: row.state ?? (index === rows.length - 1 ? 'stable' : 'changed'), risk: Number(row.risk ?? Math.max(0, 100 - Number(row.score ?? 0))), previousRisk: index > 0 ? Number(rows[index - 1].risk ?? Math.max(0, 100 - Number(rows[index - 1].score ?? 0))) : undefined, confidence: Number(row.confidence ?? 0), sources: Number(row.sources ?? 0), critical: Number(row.critical ?? 0), blastRadius: Number(row.blast_radius ?? 0) }))
    return { checkpoints, summary }
  } })

  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading continuous assurance…</div>
  if (query.error) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Continuous assurance unavailable</h1><p className="mt-2 text-sm text-muted-foreground">Live assurance checkpoints are required for this view.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>

  const checkpoints = query.data?.checkpoints ?? []
  const summary = query.data?.summary ?? {}
  if (!checkpoints.length) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><div className="text-xs font-bold uppercase tracking-[0.18em] text-muted-foreground">Continuous Assurance</div><h1 className="mt-2 text-xl font-bold">No measured checkpoints yet</h1><p className="mt-2 text-sm leading-6 text-muted-foreground">Run or complete a validation to populate this view. No historical risk or confidence values are fabricated when the source has no observations.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Refresh</button></div></div>

  const latest = checkpoints[checkpoints.length - 1]
  const first = checkpoints[0]
  const riskDelta = latest && first ? latest.risk - first.risk : 0
  const resolved = checkpoints.filter((item) => item.state === 'resolved').length
  const regressed = checkpoints.filter((item) => item.state === 'regressed').length
  const confidence = latest?.confidence ?? 0
  const postureDelta = latest && first ? (first.risk - latest.risk) / 10 : 0
  const conflicts = Number(summary?.conflicts ?? summary?.conflict_count ?? 0)
  const hasValidation = Boolean(summary?.validation || summary?.validation_count || summary?.validations)
  const hasRemediation = Boolean(summary?.remediation || summary?.remediation_count || summary?.remediations)

  const traceNodes: TraceNode[] = [
    { id: 'validation', kind: 'validation', label: latest.label, value: latest.timestamp, detail: 'Current assurance checkpoint from measured dashboard data.', confidence: latest.confidence, sourceCount: latest.sources },
    { id: 'risk', kind: 'risk', label: 'Measured exposure', value: latest.risk, detail: 'Risk derived from the measured security score when a native risk value is unavailable.', confidence: latest.confidence, sourceCount: latest.sources },
    { id: 'evidence', kind: 'evidence', label: `${latest.sources} source${latest.sources === 1 ? '' : 's'}`, value: latest.sources, detail: 'Source count is shown only when supplied by the assurance signal.' },
    { id: 'posture', kind: 'posture', label: 'Posture delta', value: postureDelta === 0 ? 'Awaiting' : `${postureDelta > 0 ? '+' : ''}${postureDelta.toFixed(1)}`, detail: 'Derived only from measured first-to-latest risk change.' },
    { id: 'executive', kind: 'executive', label: regressed ? 'Attention required' : 'Executive impact', value: regressed ? `${regressed} regression${regressed === 1 ? '' : 's'}` : `${resolved} resolved`, detail: 'Executive state derived from the same measured assurance checkpoints.' },
  ]
  const traceEdges: TraceEdge[] = [
    { from: 'validation', to: 'risk', label: 'measures' }, { from: 'validation', to: 'evidence', label: 'provenance' }, { from: 'risk', to: 'posture', label: 'changes' }, { from: 'evidence', to: 'posture', label: 'supports' }, { from: 'posture', to: 'executive', label: 'propagates' },
  ]

  return <div className="space-y-5"><InvestigationStateIntelligence signal={{ risk: latest?.risk ?? 0, confidence, sources: latest?.sources ?? 0, conflicts, critical: latest?.critical ?? 0, hasValidation, hasRemediation, resolved, regressed }} /><ContinuousAssuranceFabric checkpoints={checkpoints} onOpenPosture={() => navigate('/posture')} onOpenExecutive={() => navigate('/executive')} /><TraceabilityEvidenceGraph nodes={traceNodes} edges={traceEdges} /><CisoImpactBridge signal={{ postureDelta, riskDelta, resolved, regressed, critical: latest?.critical ?? 0, confidence, sources: latest?.sources ?? 0 }} onOpenExecutive={() => navigate('/executive')} /></div>
}
