import { useCallback, useEffect, useState } from 'react'
import { FlaskConical, RefreshCw, ShieldCheck } from 'lucide-react'
import { apiHelpers } from '@/services/api'

type Policy = { id: string; name: string; version?: number; enabled: boolean; priority: number; when: Record<string, unknown>; actions: Record<string, unknown> }
type Action = { actionId: string; title: string }
type Result = { actionId: string; current: Record<string, unknown>; proposed: Record<string, unknown>; impact: { approvalDelta: number; slaDeltaHours: number; escalationDelta: number; governanceImpact: string }; safeToPublish: boolean }

export function PolicySimulationPage() {
  const [policies, setPolicies] = useState<Policy[]>([])
  const [actions, setActions] = useState<Action[]>([])
  const [selectedPolicy, setSelectedPolicy] = useState('')
  const [actionId, setActionId] = useState('')
  const [result, setResult] = useState<Result | null>(null)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setError('')
    try {
      const [policyPayload, actionPayload] = await Promise.all([
        apiHelpers.get<{ items?: Policy[] }>('/assurance/policies'),
        apiHelpers.get<{ items?: Action[] }>('/assurance/actions'),
      ])
      const nextPolicies = policyPayload.items ?? []
      const nextActions = actionPayload.items ?? []
      setPolicies(nextPolicies)
      setActions(nextActions)
      setSelectedPolicy(current => current && nextPolicies.some(p => p.id === current) ? current : nextPolicies[0]?.id ?? '')
      setActionId(current => current && nextActions.some(a => a.actionId === current) ? current : nextActions[0]?.actionId ?? '')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to load simulation data')
    }
  }, [])

  useEffect(() => { void load() }, [load])

  const run = async () => {
    const policy = policies.find(item => item.id === selectedPolicy)
    if (!policy || !actionId) {
      setError('A persisted policy and live action are required for simulation.')
      return
    }
    setError('')
    try {
      const response = await apiHelpers.post<Result>('/assurance/policies/simulate', { action_id: actionId, policy })
      setResult(response)
    } catch (cause) {
      setResult(null)
      setError(cause instanceof Error ? cause.message : 'Simulation failed')
    }
  }

  return <div className="space-y-5">
    <header><div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Governance laboratory</div><h1 className="mt-1 text-2xl font-black tracking-tight">Policy What-If Simulator</h1><p className="mt-1 max-w-3xl text-sm text-muted-foreground">Preview approval, SLA and escalation impact against a persisted policy and a live assurance action.</p></header>
    {error && <div className="rounded-xl border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive">{error}</div>}
    <section className="rounded-2xl border bg-card p-5"><div className="grid gap-4 md:grid-cols-[1fr_1fr_auto] md:items-end">
      <label className="text-xs font-semibold">Action<select value={actionId} onChange={e => setActionId(e.target.value)} className="mt-2 w-full rounded-lg border bg-background px-3 py-2 text-sm font-normal"><option value="">Select a live action</option>{actions.map(a => <option key={a.actionId} value={a.actionId}>{a.title}</option>)}</select></label>
      <label className="text-xs font-semibold">Persisted policy<select value={selectedPolicy} onChange={e => setSelectedPolicy(e.target.value)} className="mt-2 w-full rounded-lg border bg-background px-3 py-2 text-sm font-normal"><option value="">Select a policy</option>{policies.map(p => <option key={`${p.id}-${p.version ?? 1}`} value={p.id}>{p.name} · v{p.version ?? 1}</option>)}</select></label>
      <button type="button" onClick={() => void run()} disabled={!selectedPolicy || !actionId} className="inline-flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-xs font-semibold text-primary-foreground disabled:opacity-50"><FlaskConical className="h-3.5 w-3.5"/>Simulate</button>
    </div></section>
    {!policies.length || !actions.length ? <section className="rounded-2xl border border-dashed p-8 text-sm text-muted-foreground">No persisted policy/action data is available yet. Nothing synthetic is displayed.</section> : null}
    {result && <><div className="grid gap-3 md:grid-cols-3"><Metric label="Governance" value={result.impact.governanceImpact}/><Metric label="Approval delta" value={`${result.impact.approvalDelta >= 0 ? '+' : ''}${result.impact.approvalDelta}`}/><Metric label="SLA delta" value={`${result.impact.slaDeltaHours >= 0 ? '+' : ''}${result.impact.slaDeltaHours}h`}/></div><section className="grid gap-4 md:grid-cols-2"><Compare title="Current policy" data={result.current}/><Compare title="Proposed policy" data={result.proposed}/></section><div className="flex items-center gap-2 rounded-xl border bg-card p-4 text-xs"><ShieldCheck className="h-4 w-4"/>{result.safeToPublish ? 'Simulation passed the server-side policy safety checks.' : 'Simulation requires review before publication.'}</div></>}
    <button type="button" onClick={() => void load()} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold"><RefreshCw className="h-3.5 w-3.5"/>Reload live data</button>
  </div>
}

function Metric({ label, value }: { label: string; value: string }) { return <div className="rounded-xl border bg-card p-4"><div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div><div className="mt-1 text-xl font-black">{value}</div></div> }
function Compare({ title, data }: { title: string; data: Record<string, unknown> }) { const name = String(data.policyName ?? 'Unknown'); const version = String(data.policyVersion ?? '—'); const approval = `${String(data.approvalRole ?? '—')} · ${String(data.approvalCount ?? '—')}`; const sla = `${String(data.slaHours ?? '—')}h`; const escalation = Array.isArray(data.escalationTargets) ? data.escalationTargets.join(' → ') || 'None' : 'None'; return <div className="rounded-2xl border bg-card p-5"><div className="font-semibold">{title}</div><div className="mt-4 grid grid-cols-2 gap-3"><Metric label="Policy" value={`${name} v${version}`}/><Metric label="Approval" value={approval}/><Metric label="SLA" value={sla}/><Metric label="Escalation" value={escalation}/></div></div> }
