import { useEffect, useState } from 'react'
import { Play, Plus, ShieldCheck } from 'lucide-react'
import { apiHelpers } from '@/services/api'

type Policy = {
  id: string
  version: number
  name: string
  enabled: boolean
  priority: number
  when: Record<string, unknown>
  actions: Record<string, unknown>
  createdBy?: string
  createdAt?: string
}

type SimulationResult = Record<string, unknown>

const emptyPolicy: Policy = {
  id: 'custom-policy', version: 1, name: 'New assurance policy', enabled: true, priority: 50, when: {},
  actions: { approval_role: 'security_manager', approval_count: 1, sla_hours: 24, escalate_after_minutes: 360, escalation_targets: ['security_manager'] },
}

export function PolicyStudioPage() {
  const [policies, setPolicies] = useState<Policy[]>([])
  const [draft, setDraft] = useState<Policy>(emptyPolicy)
  const [selected, setSelected] = useState('')
  const [simulation, setSimulation] = useState<SimulationResult | null>(null)
  const [error, setError] = useState('')

  const load = async () => {
    try { const response = await apiHelpers.get<{ items?: Policy[] }>('/assurance/policies'); setPolicies(response.items ?? []); setError('') }
    catch (err) { setError(err instanceof Error ? err.message : 'Unable to load policies') }
  }
  useEffect(() => { void load() }, [])
  const save = async () => {
    try { if (selected) await apiHelpers.put(`/assurance/policies/${selected}`, draft); else await apiHelpers.post('/assurance/policies', draft); await load() }
    catch (err) { setError(err instanceof Error ? err.message : 'Unable to save policy') }
  }
  const simulate = () => {
    if (!selected) { setSimulation({ error: 'Select an existing policy and action to simulate.' }); return }
    setSimulation({ policyId: selected, message: 'Simulation uses the current persisted policy version when evaluated against a live action.' })
  }

  return (
    <div className="space-y-5">
      <header><div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Governance engineering</div><h1 className="mt-1 text-2xl font-black tracking-tight">Policy Studio</h1><p className="mt-1 max-w-3xl text-sm text-muted-foreground">Author, version and inspect policy-as-code rules that control approval, SLA and escalation decisions.</p></header>
      {error && <div className="rounded-xl border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive">{error}</div>}
      <div className="grid gap-5 xl:grid-cols-[.9fr_1.1fr]">
        <section className="overflow-hidden rounded-2xl border bg-card"><header className="flex items-center justify-between border-b px-5 py-4"><div className="flex items-center gap-2 font-semibold"><ShieldCheck className="h-4 w-4 text-primary" /> Persisted policies</div><button type="button" onClick={() => { setSelected(''); setDraft(emptyPolicy) }} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><Plus className="h-3.5 w-3.5" /> New</button></header><div className="divide-y">{policies.map((policy) => <button key={`${policy.id}-${policy.version}`} type="button" onClick={() => { setSelected(policy.id); setDraft(policy) }} className={`w-full p-4 text-left hover:bg-muted/40 ${selected === policy.id ? 'bg-primary/5' : ''}`}><div className="flex items-center justify-between gap-3"><span className="text-sm font-semibold">{policy.name}</span><span className="rounded-full border px-2 py-0.5 text-[9px]">v{policy.version}</span></div><div className="mt-1 text-[10px] text-muted-foreground">{policy.id} · priority {policy.priority} · {policy.enabled ? 'enabled' : 'disabled'}</div></button>)}{!policies.length && <div className="p-8 text-sm text-muted-foreground">No policies available.</div>}</div></section>
        <section className="space-y-4"><div className="rounded-2xl border bg-card p-5"><div className="text-xs font-semibold">Rule definition</div><div className="mt-4 grid gap-3 sm:grid-cols-2"><label className="text-[10px] text-muted-foreground">ID<input value={draft.id} onChange={(event) => setDraft({ ...draft, id: event.target.value })} className="mt-1 w-full rounded-lg border bg-background px-3 py-2 text-xs text-foreground" /></label><label className="text-[10px] text-muted-foreground">Name<input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} className="mt-1 w-full rounded-lg border bg-background px-3 py-2 text-xs text-foreground" /></label><label className="text-[10px] text-muted-foreground">Priority<input type="number" value={draft.priority} onChange={(event) => setDraft({ ...draft, priority: Number(event.target.value) })} className="mt-1 w-full rounded-lg border bg-background px-3 py-2 text-xs text-foreground" /></label><label className="flex items-center gap-2 pt-5 text-xs"><input type="checkbox" checked={draft.enabled} onChange={(event) => setDraft({ ...draft, enabled: event.target.checked })} /> Enabled</label></div><label className="mt-3 block text-[10px] text-muted-foreground">Conditions (JSON)<textarea value={JSON.stringify(draft.when, null, 2)} onChange={(event) => { try { setDraft({ ...draft, when: JSON.parse(event.target.value) as Record<string, unknown> }) } catch { /* keep last valid JSON */ } }} rows={6} className="mt-1 w-full rounded-xl border bg-background p-3 font-mono text-xs text-foreground" /></label><label className="mt-3 block text-[10px] text-muted-foreground">Actions (JSON)<textarea value={JSON.stringify(draft.actions, null, 2)} onChange={(event) => { try { setDraft({ ...draft, actions: JSON.parse(event.target.value) as Record<string, unknown> }) } catch { /* keep last valid JSON */ } }} rows={8} className="mt-1 w-full rounded-xl border bg-background p-3 font-mono text-xs text-foreground" /></label><div className="mt-4 flex gap-2"><button type="button" onClick={() => void save()} className="rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground">Save new version</button><button type="button" onClick={simulate} className="inline-flex items-center gap-2 rounded-lg border px-4 py-2 text-xs font-semibold hover:bg-muted"><Play className="h-3.5 w-3.5" /> Simulate</button></div></div>{simulation && <div className="rounded-2xl border bg-card p-5"><div className="text-xs font-semibold">Simulation result</div><pre className="mt-3 overflow-auto rounded-xl border bg-muted/20 p-3 text-[10px]">{JSON.stringify(simulation, null, 2)}</pre></div>}</section>
      </div>
    </div>
  )
}
