import { useEffect, useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import {
  Activity,
  AlertCircle,
  Bot,
  Boxes,
  CheckCircle2,
  Database,
  KeyRound,
  Play,
  RefreshCw,
  ShieldCheck,
  Terminal,
} from 'lucide-react'
import { toast } from 'sonner'

import { apiHelpers } from '@/services/api'
import { useLanguageStore } from '@/stores/languageStore'

type Project = { id: string; name: string }
type ProjectsResponse = Project[] | { items?: Project[]; results?: Project[] }
type PlaneKey = 'provider' | 'crypto' | 'lifecycle' | 'fair' | 'agentic' | 'replay'
type PlaneState = {
  key: PlaneKey
  label: string
  description: string
  rows: any[]
  error: string
}
type GovernedOperation = {
  id: string
  plane: string
  label: string
  description: string
  template: Record<string, unknown>
  endpoint: (projectId: string, payload: Record<string, any>) => string
  body?: (projectId: string, payload: Record<string, any>) => unknown
}

const unwrapProjects = (data: ProjectsResponse | undefined): Project[] =>
  Array.isArray(data) ? data : data?.items ?? data?.results ?? []

const errorMessage = (error: any) => {
  const detail = error?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map((item) => typeof item === 'string' ? item : item?.msg ?? JSON.stringify(item)).join(', ')
  return error?.message || 'Request failed'
}

const without = (payload: Record<string, any>, ...keys: string[]) =>
  Object.fromEntries(Object.entries(payload).filter(([key]) => !keys.includes(key)))

const planes: Array<{
  key: PlaneKey
  label: string
  description: string
  endpoint: (projectId: string) => string
  latest: (rows: any[]) => string
}> = [
  {
    key: 'provider',
    label: 'Provider Approval',
    description: 'Approval, revocation, trust and supply-chain admissibility.',
    endpoint: (projectId) => `/provider-approvals/projects/${projectId}/decisions`,
    latest: (rows) => rows[0] ? `${rows[0].status ?? 'unknown'} · ${rows[0].trust_state ?? 'unknown'} · v${rows[0].decision_version ?? '—'}` : 'No decisions recorded',
  },
  {
    key: 'crypto',
    label: 'Cryptographic Assets / CBOM',
    description: 'Governed crypto inventory, CBOM lineage and drift.',
    endpoint: (projectId) => `/crypto-assets/projects/${projectId}/inventory`,
    latest: (rows) => rows[0] ? `snapshot v${rows[0].snapshot_version ?? '—'} · ${String(rows[0].cbom_sha256 ?? '').slice(0, 12) || 'no digest'}` : 'No inventory snapshots',
  },
  {
    key: 'lifecycle',
    label: 'Crypto Lifecycle / PQC',
    description: 'Lifecycle posture, weak crypto and PQC transition readiness.',
    endpoint: (projectId) => `/crypto-lifecycle/projects/${projectId}/assessments`,
    latest: (rows) => rows[0] ? `${rows[0].lifecycle_state ?? 'unknown'} · PQC ${rows[0].pqc_readiness ?? 'unknown'}` : 'No lifecycle assessments',
  },
  {
    key: 'fair',
    label: 'FAIR Quantitative Risk',
    description: 'Evidence-bound Monte Carlo loss exposure and assumptions.',
    endpoint: (projectId) => `/fair-risk/projects/${projectId}/analyses`,
    latest: (rows) => rows[0] ? `P95 ${rows[0].currency ?? ''} ${rows[0].annual_loss_p95 ?? '—'} · v${rows[0].analysis_version ?? '—'}` : 'No FAIR analyses',
  },
  {
    key: 'agentic',
    label: 'AI / Agentic Security',
    description: 'Provider-pinned agent profiles and governed tool authorization.',
    endpoint: (projectId) => `/agentic-security/projects/${projectId}/profiles`,
    latest: (rows) => rows[0] ? `${rows[0].agent_name ?? 'agent'} ${rows[0].agent_version ?? ''} · ${rows[0].model_name ?? 'model'}` : 'No agent profiles',
  },
  {
    key: 'replay',
    label: 'Attack Replay Sandbox',
    description: 'Isolated deterministic replay against expected controls.',
    endpoint: (projectId) => `/attack-replay/projects/${projectId}/scenarios`,
    latest: (rows) => rows[0] ? `scenario ${String(rows[0].scenario_sha256 ?? '').slice(0, 12) || (rows[0].id ?? 'recorded')}` : 'No replay scenarios',
  },
]

const operations: GovernedOperation[] = [
  {
    id: 'provider-decision',
    plane: 'Provider Approval',
    label: 'Record provider decision',
    description: 'Create an immutable approval/restriction/revocation decision with supply-chain evidence.',
    template: {
      provider_name: '',
      provider_version: '',
      capability: '',
      status: 'approved',
      manifest: {
        license: '',
        maintenance: { status: 'active' },
        sbom: true,
        supply_chain_integrity: true,
        sbom_sha256: '',
        provenance_sha256: '',
        artifact_sha256: '',
        signature_identity: '',
        signature_verified: false,
        ci_reproducibility: true,
        determinism: true,
        evidence_quality: true,
        container_privileges: [],
        network_permissions: ['authorized-target-only'],
        unmitigated_critical_cves: [],
      },
      rationale: '',
    },
    endpoint: (projectId) => `/provider-approvals/projects/${projectId}/decisions`,
  },
  {
    id: 'provider-evaluate',
    plane: 'Provider Approval',
    label: 'Evaluate provider admissibility',
    description: 'Fail-closed evaluation of current provider version, capability and pinned governance decision.',
    template: {
      provider_name: '',
      provider_version: '',
      capability: '',
      expected_legacy_approval_id: null,
      expected_decision_id: null,
    },
    endpoint: (projectId) => `/provider-approvals/projects/${projectId}/evaluate`,
  },
  {
    id: 'crypto-inventory',
    plane: 'Cryptographic Assets / CBOM',
    label: 'Record crypto inventory',
    description: 'Commit an authorized cryptographic inventory snapshot and deterministic CBOM.',
    template: {
      asset_id: '',
      authorization_id: '',
      scan_id: null,
      source_type: 'governed-ui',
      records: [
        {
          kind: 'certificate',
          name: '',
          algorithm: '',
          key_size: null,
          curve: '',
          protocol: '',
          version: '',
          issuer: '',
          subject: '',
          not_before: null,
          not_after: null,
          metadata: {},
        },
      ],
    },
    endpoint: (projectId) => `/crypto-assets/projects/${projectId}/inventory`,
  },
  {
    id: 'crypto-lifecycle',
    plane: 'Crypto Lifecycle / PQC',
    label: 'Evaluate crypto lifecycle',
    description: 'Evaluate an existing inventory snapshot for weak, expired and quantum-vulnerable crypto.',
    template: { snapshot_id: '' },
    endpoint: (_projectId, payload) => `/crypto-lifecycle/snapshots/${payload.snapshot_id}/evaluate`,
    body: () => ({}),
  },
  {
    id: 'fair-analysis',
    plane: 'FAIR Quantitative Risk',
    label: 'Run FAIR analysis',
    description: 'Execute evidence-linked deterministic Monte Carlo quantitative risk analysis.',
    template: {
      risk_correlation_id: '',
      assumptions: {
        threat_event_frequency: { low: 0, mode: 0, high: 0 },
        vulnerability: { low: 0, mode: 0, high: 0 },
        primary_loss_magnitude: { low: 0, mode: 0, high: 0 },
        secondary_event_probability: { low: 0, mode: 0, high: 0 },
        secondary_loss_magnitude: { low: 0, mode: 0, high: 0 },
      },
      assumption_evidence: {
        threat_event_frequency: [],
        vulnerability: [],
        primary_loss_magnitude: [],
        secondary_event_probability: [],
        secondary_loss_magnitude: [],
      },
      iterations: 10000,
      seed: 1,
      currency: 'USD',
    },
    endpoint: (projectId) => `/fair-risk/projects/${projectId}/analyses`,
  },
  {
    id: 'agentic-profile',
    plane: 'AI / Agentic Security',
    label: 'Register agent security profile',
    description: 'Bind an AI agent/model to an approved provider, tool allowlist and data/prompt policy.',
    template: {
      provider_decision_id: '',
      agent_name: '',
      agent_version: '',
      model_name: '',
      model_version: '',
      allowed_tools: {},
      data_boundaries: {},
      prompt_policy: {},
      idempotency_key: '',
    },
    endpoint: (projectId) => `/agentic-security/projects/${projectId}/profiles`,
  },
  {
    id: 'agentic-action',
    plane: 'AI / Agentic Security',
    label: 'Authorize agent action',
    description: 'Evaluate a tool invocation without persisting raw prompt or argument values.',
    template: {
      profile_id: '',
      tool_name: '',
      operation: '',
      prompt_sha256: '',
      prompt_length: 0,
      arguments_sha256: '',
      argument_keys: [],
      data_labels: [],
      risk_signals: [],
      human_approval_ref: '',
      idempotency_key: '',
    },
    endpoint: (projectId, payload) => `/agentic-security/projects/${projectId}/profiles/${payload.profile_id}/actions`,
    body: (_projectId, payload) => without(payload, 'profile_id'),
  },
  {
    id: 'replay-scenario',
    plane: 'Attack Replay Sandbox',
    label: 'Create replay scenario',
    description: 'Create an isolated deterministic scenario from a validated attack path.',
    template: {
      attack_path_validation_id: '',
      expected_controls: [{ control_id: '', expected: 'detect' }],
      idempotency_key: '',
    },
    endpoint: (projectId) => `/attack-replay/projects/${projectId}/scenarios`,
  },
  {
    id: 'replay-run',
    plane: 'Attack Replay Sandbox',
    label: 'Run replay scenario',
    description: 'Compare expected and observed controls using evidence references only.',
    template: {
      scenario_id: '',
      observed_controls: [{ control_id: '', observed: 'detected', evidence_ids: [] }],
      idempotency_key: '',
    },
    endpoint: (projectId, payload) => `/attack-replay/projects/${projectId}/scenarios/${payload.scenario_id}/runs`,
    body: (_projectId, payload) => without(payload, 'scenario_id'),
  },
  {
    id: 'iast-session',
    plane: 'IAST Enterprise Security',
    label: 'Start IAST session',
    description: 'Create an authorization-bound runtime security session for an approved instrumented target.',
    template: {
      asset_id: '',
      scan_id: '',
      authorization_id: '',
      provider_identity: '',
      instrumentation_mode: 'agent',
      idempotency_key: '',
    },
    endpoint: () => '/iast/sessions',
    body: (projectId, payload) => ({ project_id: projectId, ...payload }),
  },
  {
    id: 'iast-observation',
    plane: 'IAST Enterprise Security',
    label: 'Commit IAST observation',
    description: 'Commit a redacted runtime flow observation into governed Finding → Evidence lineage.',
    template: {
      session_id: '',
      idempotency_key: '',
      observation_kind: 'taint-flow',
      rule_id: '',
      title: '',
      description: '',
      severity: 'medium',
      confidence: 'confirmed',
      source_kind: '',
      sink_kind: '',
      trace_id: '',
      data_labels: [],
      location: '',
      cwe_id: '',
      owasp_category: '',
      remediation: '',
      method: '',
      parameter: '',
      file_path: '',
      line: null,
      function_name: '',
    },
    endpoint: (_projectId, payload) => `/iast/sessions/${payload.session_id}/observations`,
    body: (_projectId, payload) => without(payload, 'session_id'),
  },
  {
    id: 'burp-session',
    plane: 'Burp MCP Gateway',
    label: 'Start Burp MCP session',
    description: 'Create a provider-approved, target-authorized and rate-limited Burp MCP session.',
    template: {
      asset_id: '',
      scan_id: '',
      authorization_id: '',
      provider_name: 'burp-suite-mcp',
      provider_version: '',
      requested_operations: [],
      idempotency_key: '',
      credential_ref: null,
      max_invocations: 20,
      rate_limit_per_minute: 10,
      ttl_seconds: 1800,
    },
    endpoint: () => '/burp-mcp/sessions',
    body: (projectId, payload) => ({ project_id: projectId, ...payload }),
  },
  {
    id: 'burp-invoke',
    plane: 'Burp MCP Gateway',
    label: 'Invoke governed Burp operation',
    description: 'Invoke only an operation admitted by the pinned provider/session contract.',
    template: {
      session_id: '',
      operation: '',
      arguments: {},
      idempotency_key: '',
    },
    endpoint: (_projectId, payload) => `/burp-mcp/sessions/${payload.session_id}/invoke`,
    body: (_projectId, payload) => without(payload, 'session_id'),
  },
]

const statusTone = (state: PlaneState) =>
  state.error
    ? 'border-amber-500/30 bg-amber-500/5'
    : 'border-emerald-500/20 bg-emerald-500/[0.04]'

export const EnterpriseSecurityPlanesPage = () => {
  const t = useLanguageStore((state) => state.t)
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()
  const [operationId, setOperationId] = useState(operations[0].id)
  const selectedOperation = useMemo(
    () => operations.find((operation) => operation.id === operationId) ?? operations[0],
    [operationId],
  )
  const [payloadText, setPayloadText] = useState(() => JSON.stringify(operations[0].template, null, 2))
  const [submitting, setSubmitting] = useState(false)
  const [lastResult, setLastResult] = useState<unknown>(null)
  const [lastError, setLastError] = useState('')

  const projectsQuery = useQuery<ProjectsResponse>({
    queryKey: ['enterprise-security-projects'],
    queryFn: () => apiHelpers.get<ProjectsResponse>('/projects/'),
    staleTime: 30_000,
  })
  const projects = unwrapProjects(projectsQuery.data)
  const projectId = searchParams.get('project') ?? ''

  useEffect(() => {
    if (!projectId && projects.length > 0) {
      setSearchParams({ project: projects[0].id }, { replace: true })
    }
  }, [projectId, projects, setSearchParams])

  useEffect(() => {
    setPayloadText(JSON.stringify(selectedOperation.template, null, 2))
    setLastResult(null)
    setLastError('')
  }, [selectedOperation])

  const stateQuery = useQuery<PlaneState[]>({
    queryKey: ['enterprise-security-planes', projectId],
    enabled: Boolean(projectId),
    refetchOnWindowFocus: false,
    queryFn: async () => Promise.all(
      planes.map(async (plane) => {
        try {
          const response = await apiHelpers.get<any>(plane.endpoint(projectId))
          const rows = Array.isArray(response) ? response : response?.items ?? response?.results ?? []
          return {
            key: plane.key,
            label: plane.label,
            description: plane.description,
            rows,
            error: '',
          }
        } catch (error) {
          return {
            key: plane.key,
            label: plane.label,
            description: plane.description,
            rows: [],
            error: errorMessage(error),
          }
        }
      }),
    ),
  })

  const selectedProject = projects.find((project) => project.id === projectId)
  const planeStates = stateQuery.data ?? planes.map((plane) => ({
    key: plane.key,
    label: plane.label,
    description: plane.description,
    rows: [],
    error: '',
  }))

  const execute = async () => {
    if (!projectId) {
      toast.error(t('Select a project before executing a governed operation'))
      return
    }
    let payload: Record<string, any>
    try {
      payload = JSON.parse(payloadText)
      if (!payload || Array.isArray(payload) || typeof payload !== 'object') throw new Error('Payload must be a JSON object')
    } catch (error: any) {
      const message = error?.message || t('Request payload is not valid JSON')
      setLastError(message)
      toast.error(message)
      return
    }

    setSubmitting(true)
    setLastError('')
    setLastResult(null)
    try {
      const endpoint = selectedOperation.endpoint(projectId, payload)
      const body = selectedOperation.body ? selectedOperation.body(projectId, payload) : payload
      const result = await apiHelpers.post<unknown>(endpoint, body)
      setLastResult(result)
      await queryClient.invalidateQueries({ queryKey: ['enterprise-security-planes', projectId] })
      toast.success(t('Governed operation completed'))
    } catch (error) {
      const message = errorMessage(error)
      setLastError(message)
      toast.error(message)
    } finally {
      setSubmitting(false)
    }
  }

  return <div className="space-y-6 pb-12">
    <header className="enterprise-card overflow-hidden rounded-3xl border">
      <div className="grid gap-6 p-6 lg:grid-cols-[1fr_auto] lg:items-end">
        <div>
          <div className="inline-flex items-center gap-2 rounded-full border bg-background/60 px-3 py-1 text-xs font-semibold text-primary">
            <ShieldCheck className="h-3.5 w-3.5" />
            {t('Enterprise control plane')}
          </div>
          <h1 className="mt-3 text-3xl font-semibold tracking-tight">{t('Enterprise Security Planes')}</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
            {t('Operate governed IAST, Burp MCP, provider approval, cryptographic inventory, PQC lifecycle, FAIR risk, AI agent controls and attack replay from one project-scoped workspace. No synthetic security state is shown.')}
          </p>
        </div>
        <div className="min-w-[280px]">
          <label className="text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">{t('Project scope')}</label>
          <select
            value={projectId}
            onChange={(event) => setSearchParams({ project: event.target.value })}
            disabled={projectsQuery.isLoading || projects.length === 0}
            className="mt-2 h-11 w-full rounded-xl border bg-background px-3 text-sm"
          >
            {projects.length === 0 && <option value="">{projectsQuery.isLoading ? t('Loading projects…') : t('No accessible projects')}</option>}
            {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
          </select>
          {selectedProject && <div className="mt-2 font-mono text-[10px] text-muted-foreground">{selectedProject.id}</div>}
        </div>
      </div>
    </header>

    {projectsQuery.isError && <section className="rounded-2xl border border-destructive/30 bg-destructive/5 p-5">
      <div className="flex items-center gap-2 font-semibold text-destructive"><AlertCircle className="h-4 w-4" />{t('Project registry unavailable')}</div>
      <p className="mt-2 text-sm text-muted-foreground">{t('Enterprise operations remain disabled until an authorized project can be resolved from the API.')}</p>
    </section>}

    <section>
      <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">{t('Live governed state')}</h2>
          <p className="text-sm text-muted-foreground">{t('Immutable and policy-governed records returned by the current project APIs.')}</p>
        </div>
        <button
          type="button"
          onClick={() => stateQuery.refetch()}
          disabled={!projectId || stateQuery.isFetching}
          className="inline-flex items-center gap-2 rounded-xl border bg-card px-3 py-2 text-xs font-semibold disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${stateQuery.isFetching ? 'animate-spin' : ''}`} />
          {t('Refresh')}
        </button>
      </div>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {planeStates.map((state) => {
          const definition = planes.find((plane) => plane.key === state.key)!
          return <article key={state.key} className={`rounded-2xl border p-4 ${statusTone(state)}`}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="font-semibold">{t(state.label)}</h3>
                <p className="mt-1 text-xs leading-5 text-muted-foreground">{t(state.description)}</p>
              </div>
              {state.error ? <AlertCircle className="h-5 w-5 shrink-0 text-amber-500" /> : <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-500" />}
            </div>
            <div className="mt-4 flex items-end justify-between gap-4">
              <div>
                <div className="text-2xl font-semibold">{state.error ? '—' : state.rows.length}</div>
                <div className="text-[10px] uppercase tracking-[0.14em] text-muted-foreground">{t('records')}</div>
              </div>
              <div className="max-w-[70%] text-right text-xs text-muted-foreground">
                {state.error ? state.error : definition.latest(state.rows)}
              </div>
            </div>
          </article>
        })}
      </div>
    </section>

    <section className="grid gap-3 md:grid-cols-2">
      <div className="rounded-2xl border bg-card p-4">
        <div className="flex items-center gap-2"><Activity className="h-4 w-4 text-primary" /><h3 className="font-semibold">{t('IAST Enterprise Security')}</h3></div>
        <p className="mt-2 text-xs leading-5 text-muted-foreground">{t('Session-based runtime observations are created through authorization-bound APIs and immediately project to governed evidence and findings.')}</p>
      </div>
      <div className="rounded-2xl border bg-card p-4">
        <div className="flex items-center gap-2"><Terminal className="h-4 w-4 text-primary" /><h3 className="font-semibold">{t('Burp MCP Gateway')}</h3></div>
        <p className="mt-2 text-xs leading-5 text-muted-foreground">{t('Provider-pinned Burp operations remain rate-limited, target-authorized, credential-scoped and evidence-qualified.')}</p>
      </div>
    </section>

    <section className="enterprise-card rounded-3xl border p-5">
      <div className="flex flex-col gap-4 border-b pb-5 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="flex items-center gap-2"><KeyRound className="h-4 w-4 text-primary" /><h2 className="text-lg font-semibold">{t('Governed operation console')}</h2></div>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t('Advanced operators can submit exact API contracts without bypassing authorization, provider, tenant, evidence or audit controls.')}</p>
        </div>
        <select
          value={operationId}
          onChange={(event) => setOperationId(event.target.value)}
          className="h-11 min-w-[300px] rounded-xl border bg-background px-3 text-sm"
        >
          {operations.map((operation) => <option key={operation.id} value={operation.id}>{operation.plane} · {operation.label}</option>)}
        </select>
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-[1.15fr_.85fr]">
        <div>
          <div className="flex items-start gap-3">
            <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border bg-primary/5 text-primary"><Boxes className="h-4 w-4" /></div>
            <div>
              <div className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">{t(selectedOperation.plane)}</div>
              <h3 className="mt-1 font-semibold">{t(selectedOperation.label)}</h3>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">{t(selectedOperation.description)}</p>
            </div>
          </div>
          <label className="mt-5 block">
            <span className="text-xs font-semibold uppercase tracking-[0.12em] text-muted-foreground">{t('Request payload')}</span>
            <textarea
              spellCheck={false}
              value={payloadText}
              onChange={(event) => setPayloadText(event.target.value)}
              rows={22}
              className="mt-2 w-full rounded-2xl border bg-slate-950 p-4 font-mono text-xs leading-5 text-slate-100 outline-none focus:ring-2 focus:ring-primary/30"
            />
          </label>
          <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
            <p className="max-w-2xl text-[11px] leading-5 text-muted-foreground">
              {t('Templates intentionally contain no fabricated evidence, credentials or authorization identifiers. Supply real governed references before execution.')}
            </p>
            <button
              type="button"
              onClick={execute}
              disabled={!projectId || submitting}
              className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-50"
            >
              <Play className="h-4 w-4" />
              {submitting ? t('Executing…') : t('Execute governed operation')}
            </button>
          </div>
        </div>

        <div className="rounded-2xl border bg-muted/10 p-4">
          <div className="flex items-center gap-2"><Database className="h-4 w-4 text-primary" /><h3 className="font-semibold">{t('Result / lineage')}</h3></div>
          <p className="mt-1 text-xs text-muted-foreground">{t('Only the server response is rendered. Failed authorization and policy decisions remain fail-closed.')}</p>
          <div className="mt-4 min-h-[420px] overflow-auto rounded-xl border bg-background p-3">
            {lastError ? <div className="flex gap-2 text-sm text-destructive"><AlertCircle className="mt-0.5 h-4 w-4 shrink-0" /><span>{lastError}</span></div> :
              lastResult ? <pre className="whitespace-pre-wrap break-words font-mono text-[11px] leading-5">{JSON.stringify(lastResult, null, 2)}</pre> :
                <div className="grid min-h-[390px] place-items-center text-center text-xs text-muted-foreground"><div><Bot className="mx-auto mb-3 h-7 w-7 opacity-50" />{t('No operation has been executed in this view.')}</div></div>}
          </div>
        </div>
      </div>
    </section>
  </div>
}
