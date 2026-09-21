import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  ExternalLink,
  ListTodo,
  RefreshCw,
  Search,
  ShieldCheck,
  TimerReset,
  UserCheck,
} from 'lucide-react'

import { apiHelpers } from '@/services/api'
import { agomSdk, buildAgomIdempotencyKey, getAgomErrorMessage } from '@/services/agom'
import type { AgomClaimState, AgomWorkItem, AgomWorkSourceType } from '@/contracts/agom'
import { useLanguageStore } from '@/stores/languageStore'

type Project = { id: string; name: string }
type ProjectsResponse = Project[] | { items?: Project[]; results?: Project[] }

const unwrapProjects = (value: ProjectsResponse | undefined): Project[] =>
  Array.isArray(value) ? value : value?.items ?? value?.results ?? []

const SOURCE_OPTIONS: Array<{ value: AgomWorkSourceType | ''; label: string }> = [
  { value: '', label: 'All sources' },
  { value: 'governed_action_request', label: 'Governed requests' },
  { value: 'decision_action', label: 'Decision actions' },
  { value: 'assurance_obligation', label: 'Assurance obligations' },
  { value: 'investigation_case', label: 'Investigation cases' },
  { value: 'detection_delivery', label: 'Detection delivery' },
]

const CLAIM_OPTIONS: Array<{ value: AgomClaimState | ''; label: string }> = [
  { value: '', label: 'All claims' },
  { value: 'mine', label: 'My work' },
  { value: 'unclaimed', label: 'Unclaimed' },
  { value: 'claimed', label: 'Claimed' },
  { value: 'expired', label: 'Expired lease' },
]

const sourceLabel = (source: AgomWorkSourceType) =>
  SOURCE_OPTIONS.find((option) => option.value === source)?.label ?? source.replace(/_/g, ' ')

const destinationFor = (item: AgomWorkItem) => {
  switch (item.source_type) {
    case 'decision_action':
      return `/assurance/actions/${encodeURIComponent(item.source_id)}`
    case 'investigation_case':
      return '/investigation'
    case 'assurance_obligation':
      return '/assurance/continuous'
    case 'detection_delivery':
    case 'governed_action_request':
      return '/assurance/governance'
  }
}

const idempotencyKeyFor = (operation: 'claim' | 'renew' | 'release', item: AgomWorkItem) => {
  const source = item.source_id.length <= 72
    ? item.source_id
    : `${item.source_id.slice(0, 32)}-${item.source_id.slice(-32)}`
  return buildAgomIdempotencyKey(
    'ops',
    operation,
    item.source_type,
    source,
    `v${item.claim.version}`,
  )
}

const timestamp = (value: string | null) => {
  if (!value) return 'No deadline'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

const claimTone = (item: AgomWorkItem) => {
  if (item.claim.mine) return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
  if (item.claim.state === 'expired') return 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400'
  if (item.claim.state === 'claimed') return 'border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400'
  return 'border-border bg-muted/20 text-muted-foreground'
}

export function WorkflowControlTowerPage() {
  useLanguageStore((state) => state.language)
  const [projectId, setProjectId] = useState('')
  const [sourceFilter, setSourceFilter] = useState<AgomWorkSourceType | ''>('')
  const [claimFilter, setClaimFilter] = useState<AgomClaimState | ''>('')
  const [search, setSearch] = useState('')
  const [busyKey, setBusyKey] = useState('')
  const [actionError, setActionError] = useState('')
  const [notice, setNotice] = useState('')

  const projectsQuery = useQuery({
    queryKey: ['operations-projects'],
    queryFn: () => apiHelpers.get<ProjectsResponse>('/projects/'),
    staleTime: 30_000,
  })
  const projects = unwrapProjects(projectsQuery.data)

  useEffect(() => {
    if (!projectId && projects[0]?.id) setProjectId(projects[0].id)
  }, [projectId, projects])

  const queue = useQuery({
    queryKey: ['agom-operational-workspace', projectId, sourceFilter, claimFilter],
    enabled: Boolean(projectId),
    queryFn: () => agomSdk.listWorkQueue({
      project_id: projectId,
      source_type: sourceFilter || undefined,
      claim_state: claimFilter || undefined,
      limit: 500,
    }),
    refetchInterval: 15_000,
  })

  const authorityOrganizationId = queue.data?.items[0]?.organization_id ?? ''
  const authority = useQuery({
    queryKey: ['agom-operational-authority', authorityOrganizationId, projectId],
    enabled: Boolean(authorityOrganizationId && projectId),
    queryFn: () => agomSdk.getAuthority({
      organizationId: authorityOrganizationId,
      projectId,
    }),
  })
  const canMutateClaims = Boolean(
    authority.data && ['owner', 'admin', 'manager', 'analyst'].includes(authority.data.role),
  )

  const items = useMemo(() => {
    const needle = search.trim().toLowerCase()
    if (!needle) return queue.data?.items ?? []
    return (queue.data?.items ?? []).filter((item) => [
      item.title,
      item.work_category,
      item.authoritative_state,
      item.source_type,
      item.source_id,
      String(item.details.action_id ?? ''),
      String(item.details.kind ?? ''),
      String(item.details.owner ?? ''),
    ].some((value) => value.toLowerCase().includes(needle)))
  }, [queue.data?.items, search])

  const stats = useMemo(() => {
    const source = queue.data?.items ?? []
    return {
      total: queue.data?.total ?? 0,
      returned: queue.data?.returned ?? 0,
      overdue: source.filter((item) => item.overdue).length,
      mine: source.filter((item) => item.claim.mine).length,
      unclaimed: source.filter((item) => item.claim.state === 'unclaimed').length,
      highPriority: source.filter((item) => item.priority_score >= 90).length,
    }
  }, [queue.data])

  const mutateClaim = async (operation: 'claim' | 'renew' | 'release', item: AgomWorkItem) => {
    const operationKey = `${operation}:${item.item_key}`
    setBusyKey(operationKey)
    setActionError('')
    setNotice('')
    try {
      const input = {
        project_id: item.project_id,
        expected_claim_version: item.claim.version,
        idempotency_key: idempotencyKeyFor(operation, item),
      }
      if (operation === 'claim') {
        await agomSdk.claimWork(item.source_type, item.source_id, { ...input, lease_seconds: 900 })
      } else if (operation === 'renew') {
        await agomSdk.renewWork(item.source_type, item.source_id, { ...input, lease_seconds: 900 })
      } else {
        await agomSdk.releaseWork(item.source_type, item.source_id, input)
      }
      setNotice(`${operation === 'release' ? 'Released' : operation === 'renew' ? 'Renewed' : 'Claimed'}: ${item.title}`)
      await queue.refetch()
    } catch (error) {
      setActionError(getAgomErrorMessage(error, 'Governed work mutation failed.'))
    } finally {
      setBusyKey('')
    }
  }

  const queueError = queue.error
    ? getAgomErrorMessage(queue.error, 'Unable to load governed work queue.')
    : ''

  return <div className="space-y-5 pb-10">
    <header className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
      <div>
        <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.18em] text-primary">
          <ShieldCheck className="h-4 w-4" />
          Governed operations
        </div>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight">Enterprise Operational Workspace</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          One prioritized operating queue for governed requests, remediation actions, assurance obligations,
          investigations, and failed detection deliveries. Ownership is leased here; authoritative lifecycle
          decisions remain in their source systems.
        </p>
      </div>
      <button
        type="button"
        onClick={() => void queue.refetch()}
        disabled={!projectId || queue.isFetching}
        className="inline-flex items-center gap-2 rounded-xl border bg-card px-4 py-2.5 text-sm font-medium disabled:opacity-50"
      >
        <RefreshCw className={`h-4 w-4 ${queue.isFetching ? 'animate-spin' : ''}`} />
        Refresh queue
      </button>
    </header>

    <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-6">
      {[
        ['Total actionable', stats.total],
        ['Returned', stats.returned],
        ['High priority', stats.highPriority],
        ['Overdue', stats.overdue],
        ['My leases', stats.mine],
        ['Unclaimed', stats.unclaimed],
      ].map(([label, value]) => <div key={String(label)} className="enterprise-card rounded-xl p-4">
        <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</div>
        <div className="mt-2 text-2xl font-black">{value}</div>
      </div>)}
    </section>

    <section className="enterprise-card rounded-2xl p-4">
      <div className="grid gap-3 lg:grid-cols-[1.2fr_1fr_1fr_1.6fr]">
        <label className="text-xs font-medium text-muted-foreground">
          Project
          <select
            value={projectId}
            onChange={(event) => setProjectId(event.target.value)}
            className="mt-1.5 h-10 w-full rounded-xl border bg-background px-3 text-sm text-foreground"
          >
            {!projects.length && <option value="">No project available</option>}
            {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
          </select>
        </label>
        <label className="text-xs font-medium text-muted-foreground">
          Source
          <select
            value={sourceFilter}
            onChange={(event) => setSourceFilter(event.target.value as AgomWorkSourceType | '')}
            className="mt-1.5 h-10 w-full rounded-xl border bg-background px-3 text-sm text-foreground"
          >
            {SOURCE_OPTIONS.map((option) => <option key={option.value || 'all'} value={option.value}>{option.label}</option>)}
          </select>
        </label>
        <label className="text-xs font-medium text-muted-foreground">
          Claim state
          <select
            value={claimFilter}
            onChange={(event) => setClaimFilter(event.target.value as AgomClaimState | '')}
            className="mt-1.5 h-10 w-full rounded-xl border bg-background px-3 text-sm text-foreground"
          >
            {CLAIM_OPTIONS.map((option) => <option key={option.value || 'all'} value={option.value}>{option.label}</option>)}
          </select>
        </label>
        <label className="text-xs font-medium text-muted-foreground">
          Search
          <span className="relative mt-1.5 block">
            <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2" />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Title, source, state, owner…"
              className="h-10 w-full rounded-xl border bg-background ps-9 pe-3 text-sm text-foreground"
            />
          </span>
        </label>
      </div>
      {queue.data && <div className="mt-3 flex flex-wrap gap-2 text-[10px] text-muted-foreground">
        <span>Policy {queue.data.policy_version}</span>
        {Object.entries(queue.data.counts).map(([category, count]) =>
          <span key={category} className="rounded-full border px-2 py-1">{category.replace(/_/g, ' ')} · {count}</span>)}
      </div>}
    </section>

    {authority.data && !canMutateClaims && <div className="rounded-xl border bg-muted/20 p-4 text-sm text-muted-foreground">
      Read-only governed queue. Your server-authoritative tenant role is <strong className="text-foreground">{authority.data.role}</strong>.
    </div>}

    {(actionError || queueError) && <div className="flex items-start gap-2 rounded-xl border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <span>{actionError || queueError}</span>
    </div>}
    {notice && <div className="flex items-start gap-2 rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm text-emerald-700 dark:text-emerald-300">
      <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
      <span>{notice}</span>
    </div>}

    {projectsQuery.isLoading || (projectId && queue.isLoading)
      ? <div className="enterprise-card grid min-h-56 place-items-center rounded-2xl text-sm text-muted-foreground">Loading governed operations…</div>
      : !projectId
        ? <div className="enterprise-card grid min-h-56 place-items-center rounded-2xl p-8 text-center text-sm text-muted-foreground">No accessible project is available for the operational queue.</div>
        : items.length === 0
          ? <div className="enterprise-card grid min-h-56 place-items-center rounded-2xl p-8 text-center">
              <div><ListTodo className="mx-auto h-7 w-7 text-muted-foreground" /><div className="mt-3 font-semibold">No actionable work matches this scope</div><p className="mt-1 text-sm text-muted-foreground">The queue only projects non-terminal authoritative work.</p></div>
            </div>
          : <section className="space-y-3">
              {items.map((item) => {
                const destination = destinationFor(item)
                const canClaim = canMutateClaims && (item.claim.state === 'unclaimed' || item.claim.state === 'expired')
                const canRenew = canMutateClaims && item.claim.mine
                const canRelease = canMutateClaims && item.claim.mine
                const busy = busyKey.endsWith(item.item_key)
                return <article key={item.item_key} className="enterprise-card rounded-2xl p-4 md:p-5">
                  <div className="grid gap-4 xl:grid-cols-[1fr_auto] xl:items-start">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`rounded-full border px-2 py-1 text-[10px] font-semibold ${item.priority_score >= 90 ? 'border-destructive/30 bg-destructive/10 text-destructive' : 'bg-muted/30 text-muted-foreground'}`}>
                          Priority {item.priority_score}
                        </span>
                        <span className="rounded-full border px-2 py-1 text-[10px] capitalize">{item.work_category.replace(/_/g, ' ')}</span>
                        <span className={`rounded-full border px-2 py-1 text-[10px] ${claimTone(item)}`}>
                          {item.claim.mine ? 'Mine' : item.claim.state.replace(/_/g, ' ')}
                        </span>
                        {item.overdue && <span className="rounded-full border border-destructive/30 bg-destructive/10 px-2 py-1 text-[10px] font-bold text-destructive">Overdue</span>}
                      </div>
                      <h2 className="mt-3 text-base font-semibold">{item.title}</h2>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {sourceLabel(item.source_type)} · authoritative state <strong className="text-foreground">{item.authoritative_state}</strong> · source version {item.source_version}
                      </div>
                      <div className="mt-3 grid gap-2 text-xs text-muted-foreground sm:grid-cols-2 xl:grid-cols-4">
                        <div className="rounded-xl border bg-background/40 p-3">
                          <div className="flex items-center gap-1 font-medium text-foreground"><Clock3 className="h-3.5 w-3.5" />Due</div>
                          <div className="mt-1">{timestamp(item.due_at)}</div>
                        </div>
                        <div className="rounded-xl border bg-background/40 p-3">
                          <div className="flex items-center gap-1 font-medium text-foreground"><UserCheck className="h-3.5 w-3.5" />Lease owner</div>
                          <div className="mt-1 break-all">{item.claim.claimed_by_id ?? 'Unclaimed'}</div>
                        </div>
                        <div className="rounded-xl border bg-background/40 p-3">
                          <div className="flex items-center gap-1 font-medium text-foreground"><TimerReset className="h-3.5 w-3.5" />Lease expiry</div>
                          <div className="mt-1">{timestamp(item.claim.lease_expires_at)}</div>
                        </div>
                        <div className="rounded-xl border bg-background/40 p-3">
                          <div className="font-medium text-foreground">Source identity</div>
                          <div className="mt-1 break-all font-mono text-[10px]">{item.source_id}</div>
                        </div>
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-2 xl:max-w-[280px] xl:justify-end">
                      {destination && <Link to={destination} className="inline-flex items-center gap-1.5 rounded-xl border px-3 py-2 text-xs font-semibold hover:bg-accent">
                        <ExternalLink className="h-3.5 w-3.5" />Open source
                      </Link>}
                      {canClaim && <button
                        type="button"
                        aria-label={`Claim ${item.title}`}
                        disabled={busy}
                        onClick={() => void mutateClaim('claim', item)}
                        className="rounded-xl bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground disabled:opacity-50"
                      >Claim 15 min</button>}
                      {canRenew && <button
                        type="button"
                        aria-label={`Renew ${item.title}`}
                        disabled={busy}
                        onClick={() => void mutateClaim('renew', item)}
                        className="rounded-xl border px-3 py-2 text-xs font-semibold disabled:opacity-50"
                      >Renew 15 min</button>}
                      {canRelease && <button
                        type="button"
                        aria-label={`Release ${item.title}`}
                        disabled={busy}
                        onClick={() => void mutateClaim('release', item)}
                        className="rounded-xl border px-3 py-2 text-xs font-semibold disabled:opacity-50"
                      >Release</button>}
                    </div>
                  </div>
                </article>
              })}
            </section>}
  </div>
}
