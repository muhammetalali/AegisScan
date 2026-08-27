import { useQuery } from '@tanstack/react-query'
import { RefreshCw, ShieldAlert } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { SecurityPostureEvolution, type PosturePoint } from '@/components/security/SecurityPostureEvolution'

export const SecurityPosture = () => {
  const query = useQuery({ queryKey: ['posture-evolution'], queryFn: async () => {
    const [trends, correlation] = await Promise.all([
      apiHelpers.get<any>('/dashboard/trends?days=30'),
      apiHelpers.get<any>('/assurance/correlations/summary'),
    ])
    return { trends, correlation }
  } })
  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading security posture…</div>
  if (query.error || !query.data) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Security posture unavailable</h1><p className="mt-2 text-sm text-muted-foreground">Live posture history and assurance correlation data are required.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>
  const rows = Array.isArray(query.data.trends) ? query.data.trends : query.data.trends?.results ?? query.data.trends?.items ?? []
  const points: PosturePoint[] = rows.map((row: any, index: number) => ({ label: String(row.date ?? row.label ?? `T${index + 1}`).slice(0, 10), risk: Number(row.risk ?? Math.max(0, 100 - Number(row.score ?? 0))), blastRadius: Number(row.blast_radius ?? 0), critical: Number(row.critical ?? 0), verified: Number(row.verified ?? 0) }))
  const correlation = query.data.correlation ?? {}
  if (!points.length) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">No posture history available yet.</div>
  return <div className="space-y-5"><SecurityPostureEvolution points={points} assuranceConflicts={Number(correlation.conflicts ?? 0)} assuranceConfidence={Number(correlation.confidence ?? 0)} /><div className="flex items-center justify-between gap-3 rounded-xl border bg-card px-4 py-3 text-xs"><div className="flex items-center gap-2 text-muted-foreground"><ShieldAlert className="h-4 w-4 text-amber-500" />{Number(correlation.conflicts ?? 0) > 0 ? `${correlation.conflicts} cross-source conflict(s) currently reduce assurance confidence.` : 'No cross-source conflicts currently reduce assurance confidence.'}</div><a href="/assurance/conflicts" className="font-semibold text-primary hover:underline">Review conflicts</a></div></div>
}
