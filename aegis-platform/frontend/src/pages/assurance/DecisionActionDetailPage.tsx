import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { RefreshCw } from 'lucide-react'
import { DecisionActionOrchestration, type DecisionAction } from '@/components/security/DecisionActionOrchestration'

export const DecisionActionDetailPage = () => {
  const { actionId } = useParams<{ actionId: string }>()
  const [action, setAction] = useState<DecisionAction | null>(null)
  const [error, setError] = useState('')
  const token = localStorage.getItem('access_token') || ''
  const load = async () => { try { const response = await fetch(`/api/v1/assurance/actions/${actionId}`, { headers: { Authorization: `Bearer ${token}` } }); if (!response.ok) throw new Error('Action unavailable'); setAction(await response.json()) } catch (err: any) { setError(err.message ?? 'Unable to load action') } }
  useEffect(() => { void load() }, [actionId])
  const transition = async (state: string) => { if (!actionId) return; const response = await fetch(`/api/v1/assurance/actions/${actionId}/transition`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ state }) }); if (!response.ok) throw new Error('Transition failed'); setAction(await response.json()) }
  if (error) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Action unavailable</h1><p className="mt-2 text-sm text-muted-foreground">{error}</p><button type="button" onClick={() => void load()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5" /> Retry</button></div></div>
  if (!action) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading action workspace…</div>
  return <div className="space-y-5"><header><div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Action execution</div><h1 className="mt-1 text-2xl font-black tracking-tight">{action.title}</h1><p className="mt-1 text-sm text-muted-foreground">Auditable remediation lifecycle with re-validation as the proof gate.</p></header><DecisionActionOrchestration action={action} onTransition={(state) => void transition(state)} /></div>
}
