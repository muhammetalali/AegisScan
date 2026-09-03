import { useEffect, useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { GitBranch, Layers, Play, RefreshCw } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { apiContractPaths } from '@/contracts/api'

type Project = { id: string; name: string }
type Twin = { id: string; project_id: string; name: string; status: string; environment: Record<string, unknown>; created_at: string; contract_version: '1.0'; source: 'postgresql' }
type Scenario = {
  id: string
  twin_id: string
  name: string
  change_type: string
  description: string
  affected_nodes: string[]
  security_impact: number
  performance_impact: number
  risk_reduction: number
  recommendation: string
  status: string
  created_at: string
  contract_version: '1.0'
  source: 'postgresql'
}

type ProjectsResponse = Project[] | { items?: Project[]; results?: Project[] }

const unwrapProjects = (data: ProjectsResponse | undefined): Project[] => Array.isArray(data) ? data : data?.items ?? data?.results ?? []

export const DigitalTwin = () => {
  const queryClient = useQueryClient()
  const [projectId, setProjectId] = useState('')
  const [twinId, setTwinId] = useState('')
  const [scenarioName, setScenarioName] = useState('')
  const [changeType, setChangeType] = useState('security_change')
  const [description, setDescription] = useState('')
  const [performanceImpact, setPerformanceImpact] = useState('0')
  const [affectedNodes, setAffectedNodes] = useState('')
  const [working, setWorking] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const projectsQuery = useQuery({
    queryKey: ['digital-twin-projects'],
    queryFn: () => apiHelpers.get<ProjectsResponse>('/projects/'),
    staleTime: 30_000,
  })
  const projects = useMemo(() => unwrapProjects(projectsQuery.data), [projectsQuery.data])

  useEffect(() => {
    if (!projectId && projects[0]?.id) setProjectId(projects[0].id)
  }, [projectId, projects])

  const twinsQuery = useQuery({
    queryKey: ['digital-twins', projectId],
    queryFn: () => apiHelpers.get<Twin[]>(`/digital-twin/projects/${projectId}/twins`),
    enabled: !!projectId,
    staleTime: 5_000,
  })
  const twins = twinsQuery.data ?? []

  useEffect(() => {
    if (!twinId && twins[0]?.id) setTwinId(twins[0].id)
    if (twinId && twins.length && !twins.some((t) => t.id === twinId)) setTwinId(twins[0]?.id ?? '')
  }, [twinId, twins])

  const scenariosQuery = useQuery({
    queryKey: ['digital-twin-scenarios', twinId],
    queryFn: () => apiHelpers.get<Scenario[]>(`/digital-twin/twins/${twinId}/scenarios`),
    enabled: !!twinId,
    refetchInterval: (query) => (query.state.data ?? []).some((item) => ['pending', 'running'].includes(item.status)) ? 2_000 : false,
    staleTime: 1_000,
  })
  const scenarios = scenariosQuery.data ?? []
  const latestScenario = scenarios[0]
  const selectedTwin = twins.find((t) => t.id === twinId)
  const environment = selectedTwin?.environment ?? {}

  const createTwin = async () => {
    if (!projectId) return
    setWorking(true); setError(null)
    try {
      const created = await apiHelpers.post<Twin>(`/digital-twin/projects/${projectId}/twins?name=${encodeURIComponent('Primary Digital Twin')}`)
      setTwinId(created.id)
      await queryClient.invalidateQueries({ queryKey: ['digital-twins', projectId] })
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? e?.message ?? 'Unable to create digital twin')
    } finally { setWorking(false) }
  }

  const createScenario = async () => {
    if (!twinId || !scenarioName.trim()) return
    setWorking(true); setError(null)
    try {
      await apiHelpers.post<Scenario>(`/digital-twin/twins/${twinId}/scenarios`, {
        name: scenarioName.trim(),
        change_type: changeType,
        description: description.trim(),
        affected_nodes: affectedNodes.split(',').map((v) => v.trim()).filter(Boolean),
        parameters: {},
        performance_impact: Number(performanceImpact) || 0,
      })
      setScenarioName(''); setDescription(''); setAffectedNodes(''); setPerformanceImpact('0')
      await scenariosQuery.refetch()
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? e?.message ?? 'Unable to create scenario')
    } finally { setWorking(false) }
  }

  const simulate = async (scenarioId: string) => {
    setWorking(true); setError(null)
    try {
      await apiHelpers.post(apiContractPaths.validationContract.replace('/validation-contract', `/digital-twin/scenarios/${scenarioId}/simulate`))
      await scenariosQuery.refetch()
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? e?.message ?? 'Unable to queue scenario simulation')
    } finally { setWorking(false) }
  }

  if (projectsQuery.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading projects…</div>
  if (projectsQuery.isError) return <div className="grid min-h-[70vh] place-items-center text-sm text-destructive">Projects could not be loaded.</div>

  return (
    <div className="space-y-5">
      <header>
        <h1 className="flex items-center gap-2 text-2xl font-bold"><GitBranch className="h-6 w-6 text-primary" /> Digital Twin</h1>
        <p className="text-sm text-muted-foreground">Live PostgreSQL-backed environment model and deterministic what-if simulation.</p>
      </header>

      {error && <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">{error}</div>}

      <section className="grid gap-3 lg:grid-cols-3">
        <label className="rounded-xl border bg-card p-4 text-sm"><span className="text-xs text-muted-foreground">Project</span><select value={projectId} onChange={(e) => { setProjectId(e.target.value); setTwinId('') }} className="mt-2 h-10 w-full rounded-lg border bg-background px-2">{projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
        <label className="rounded-xl border bg-card p-4 text-sm"><span className="text-xs text-muted-foreground">Digital Twin</span><select value={twinId} onChange={(e) => setTwinId(e.target.value)} className="mt-2 h-10 w-full rounded-lg border bg-background px-2">{twins.map((t) => <option key={t.id} value={t.id}>{t.name} · {t.status}</option>)}</select></label>
        <div className="rounded-xl border bg-card p-4 text-sm"><span className="text-xs text-muted-foreground">Source</span><div className="mt-2 font-medium">{selectedTwin?.source ?? 'postgresql'}</div>{!twins.length && <button type="button" onClick={createTwin} disabled={working} className="mt-3 rounded-lg bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground">Create Twin</button>}</div>
      </section>

      {selectedTwin && <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">{[['Assets', environment.node_count ?? '—'], ['Relationships', environment.relationship_count ?? '—'], ['Status', selectedTwin.status], ['Version', environment.version ?? '—'], ['Created', new Date(selectedTwin.created_at).toLocaleString()]].map(([label, value]) => <div key={String(label)} className="rounded-xl border bg-card p-4"><div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div><div className="mt-1 text-lg font-black">{String(value)}</div></div>)}</section>}

      {selectedTwin && <section className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border bg-card p-4"><h2 className="flex items-center gap-2 font-semibold"><Layers className="h-4 w-4" /> Scenario Creation</h2><div className="mt-4 grid gap-3"><input value={scenarioName} onChange={(e) => setScenarioName(e.target.value)} placeholder="Scenario name" className="h-10 rounded-lg border bg-background px-3 text-sm"/><input value={changeType} onChange={(e) => setChangeType(e.target.value)} placeholder="Change type" className="h-10 rounded-lg border bg-background px-3 text-sm"/><textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Description" rows={3} className="rounded-lg border bg-background p-3 text-sm"/><input value={affectedNodes} onChange={(e) => setAffectedNodes(e.target.value)} placeholder="Affected node IDs, comma-separated" className="h-10 rounded-lg border bg-background px-3 text-sm"/><label className="text-sm">Performance impact<input value={performanceImpact} onChange={(e) => setPerformanceImpact(e.target.value)} type="number" min="0" className="mt-1 h-10 w-full rounded-lg border bg-background px-3"/></label><button type="button" disabled={working || !scenarioName.trim()} onClick={createScenario} className="inline-flex items-center justify-center gap-2 rounded-lg bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50"><Play className="h-4 w-4" /> Create & Queue</button></div></div>
        <div className="rounded-xl border bg-card p-4"><div className="flex items-center justify-between"><h2 className="font-semibold">Persisted Scenarios</h2><button type="button" onClick={() => scenariosQuery.refetch()} className="rounded-lg border p-2" aria-label="Refresh scenarios"><RefreshCw className="h-4 w-4" /></button></div>{scenariosQuery.isLoading ? <div className="py-10 text-center text-sm text-muted-foreground">Loading scenarios…</div> : scenarios.length === 0 ? <div className="py-10 text-center text-sm text-muted-foreground">No persisted scenarios.</div> : <div className="mt-4 space-y-3">{scenarios.map((item) => <div key={item.id} className="rounded-lg border p-3"><div className="flex items-start justify-between gap-3"><div><div className="font-semibold">{item.name}</div><div className="text-xs text-muted-foreground">{item.change_type} · {item.status}</div></div><button type="button" onClick={() => simulate(item.id)} disabled={working || ['pending', 'running'].includes(item.status)} className="rounded-lg border px-3 py-1.5 text-xs font-semibold">Simulate</button></div><div className="mt-2 grid grid-cols-3 gap-2 text-xs"><div><span className="text-muted-foreground">Before</span><div className="font-bold">{item.security_impact || '—'}</div></div><div><span className="text-muted-foreground">Risk reduction</span><div className="font-bold">{item.risk_reduction}</div></div><div><span className="text-muted-foreground">Performance</span><div className="font-bold">{item.performance_impact}</div></div></div>{item.recommendation && <div className="mt-2 rounded bg-muted/20 p-2 text-xs">{item.recommendation}</div>}</div>)}</div>}</div>
      </section>}

      {latestScenario && <section className="rounded-xl border bg-card p-4"><h2 className="font-semibold">Latest persisted scenario</h2><div className="mt-3 grid gap-3 sm:grid-cols-4"><div><div className="text-xs text-muted-foreground">Name</div><div className="font-bold">{latestScenario.name}</div></div><div><div className="text-xs text-muted-foreground">Status</div><div className="font-bold">{latestScenario.status}</div></div><div><div className="text-xs text-muted-foreground">Security impact</div><div className="font-bold">{latestScenario.security_impact}</div></div><div><div className="text-xs text-muted-foreground">Risk reduction</div><div className="font-bold">{latestScenario.risk_reduction}</div></div></div></section>}
    </div>
  )
}
