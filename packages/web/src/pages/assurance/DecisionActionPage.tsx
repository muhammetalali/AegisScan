import { useCallback, useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { DecisionActionOrchestration, type DecisionAction } from '@/components/security/DecisionActionOrchestration'
import OutcomeIntelligencePanel from '@/components/security/OutcomeIntelligencePanel'

export const DecisionActionPage = () => {
  const [actions, setActions] = useState<DecisionAction[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const token = localStorage.getItem('access_token') || ''
  const load = useCallback(async () => { setLoading(true); setError(''); try { const response = await fetch('/api/v1/assurance/actions', { headers: { Authorization: `Bearer ${token}` } }); if (!response.ok) throw new Error('Decision actions unavailable'); const payload = await response.json(); setActions(payload.items ?? []) } catch (err: any) { setError(err.message ?? 'Unable to load actions') } finally { setLoading(false) } }, [token])
  useEffect(() => { void load() }, [load])
  const transition = async (actionId: string, state: string) => { const response = await fetch(`/api/v1/assurance/actions/${actionId}/transition`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ state }) }); if (!response.ok) throw new Error('Transition failed'); const updated = await response.json(); setActions((items) => items.map((item) => item.actionId === actionId ? updated : item)) }
  if (loading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading decision actions…</div>
  if (error) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Decision actions unavailable</h1><p className="mt-2 text-sm text-muted-foreground">Live orchestration state could not be retrieved.</p><button type="button" onClick={() => void load()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>
  return <div className="space-y-5"><header><div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Execution assurance</div><h1 className="mt-1 text-2xl font-black tracking-tight">Decision-to-Action Orchestration</h1><p className="mt-1 max-w-3xl text-sm text-muted-foreground">Own, execute, re-validate, and verify security decisions with an auditable lifecycle.</p></header>{actions.length ? <div className="space-y-5">{actions.map((action) => <div key={action.actionId} className="space-y-4"><DecisionActionOrchestration action={action} onTransition={(state) => void transition(action.actionId, state)} /><OutcomeIntelligencePanel action={action} /></div>)}</div> : <div className="rounded-2xl border bg-card p-10 text-center text-sm text-muted-foreground">No decision actions have been created yet. Create an action from a Security Decision.</div>}</div>
}
