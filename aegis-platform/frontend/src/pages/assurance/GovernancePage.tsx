import { useEffect, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  RefreshCw,
  ShieldCheck,
  Siren,
} from 'lucide-react'

import type { AgomContractRegistry } from '@/contracts/agom'
import { agomApi } from '@/services/agom'
import { apiHelpers } from '@/services/api'

type Item = {
  actionId: string
  title: string
  owner: string
  state: string
  priority: number
  governance: {
    policyTier: string
    approvalRequired: boolean
    approvalRole: string
    escalationTargets: string[]
    escalationLevel: number
    policySlaHours: number
    governanceState: string
    rationale: string
  }
}

type Payload = {
  items: Item[]
  metrics: {
    total: number
    approvalRequired: number
    escalated: number
    criticalPolicy: number
    breached: number
  }
}

const errorMessage = (error: unknown) => {
  const candidate = error as { response?: { data?: { detail?: unknown } }; message?: string }
  const detail = candidate?.response?.data?.detail
  if (typeof detail === 'string') return detail
  return candidate?.message || 'Unable to load governance'
}

export function GovernancePage() {
  const [data, setData] = useState<Payload | null>(null)
  const [registry, setRegistry] = useState<AgomContractRegistry | null>(null)
  const [error, setError] = useState('')

  const load = async () => {
    try {
      setError('')
      const [governance, contracts] = await Promise.all([
        apiHelpers.get<Payload>('/assurance/governance'),
        agomApi.contracts(),
      ])
      setData(governance)
      setRegistry(contracts)
    } catch (loadError) {
      setError(errorMessage(loadError))
    }
  }

  useEffect(() => {
    void load()
  }, [])

  if (error && (!data || !registry)) {
    return (
      <div className="p-8">
        <div className="text-sm text-destructive">{error}</div>
        <button
          onClick={() => void load()}
          className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Retry
        </button>
      </div>
    )
  }

  if (!data || !registry) {
    return <div className="p-8 text-sm text-muted-foreground">Loading governance intelligence…</div>
  }

  return (
    <div className="space-y-5">
      <header>
        <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
          Policy intelligence
        </div>
        <h1 className="mt-1 text-2xl font-black tracking-tight">
          Governance & Escalation Command Center
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Policy tiers, approval gates, escalation targets and SLA governance derived from live remediation actions.
        </p>
        {error && <p className="mt-2 text-xs text-destructive">{error}</p>}
      </header>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        {[
          ['Actions', data.metrics.total],
          ['Approval', data.metrics.approvalRequired],
          ['Escalated', data.metrics.escalated],
          ['Critical policy', data.metrics.criticalPolicy],
          ['Breached', data.metrics.breached],
        ].map(([key, value]) => (
          <div key={String(key)} className="rounded-xl border bg-card p-3">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{key}</div>
            <div className="mt-1 text-xl font-black">{value}</div>
          </div>
        ))}
      </div>

      <section className="overflow-hidden rounded-2xl border bg-card">
        <header className="border-b px-5 py-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2 font-semibold">
              <ShieldCheck className="h-4 w-4 text-primary" />
              Authoritative AGOM action contracts
            </div>
            <div className="text-[10px] text-muted-foreground">
              {registry.contract_version} · {registry.policy_version} · {registry.action_count} actions
            </div>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            Eligibility is evaluated by the server capability manifest. This registry is metadata and never grants client-side authority.
          </p>
        </header>
        <div className="divide-y">
          {registry.actions.map((action) => (
            <article
              key={action.action_id}
              className="grid gap-4 p-4 lg:grid-cols-[1.3fr_.8fr_1fr]"
            >
              <div>
                <div className="font-mono text-xs font-semibold">{action.action_id}</div>
                <div className="mt-1 text-sm">{action.intent}</div>
                <div className="mt-2 text-[10px] text-muted-foreground">
                  Entity {action.entity_type} · Audit {action.audit_event}
                </div>
              </div>
              <div className="rounded-xl border p-3">
                <div className="text-[9px] uppercase tracking-wider text-muted-foreground">
                  Responsibility
                </div>
                <div className="mt-1 text-xs font-semibold">
                  {action.required_responsibilities.join(', ') || 'None'}
                </div>
                <div className="mt-2 text-[10px] text-muted-foreground">
                  Roles: {action.allowed_roles.join(', ')}
                </div>
              </div>
              <div className="rounded-xl border p-3">
                <div className="text-[9px] uppercase tracking-wider text-muted-foreground">
                  Server gates
                </div>
                <div className="mt-1 text-xs font-semibold">
                  {action.required_gates.join(', ') || 'No explicit gates'}
                </div>
                <div className="mt-2 text-[10px] text-muted-foreground">
                  SoD: {action.sod_rules.join(', ') || 'None'}
                </div>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="overflow-hidden rounded-2xl border bg-card">
        <header className="border-b px-5 py-4">
          <div className="flex items-center gap-2 font-semibold">
            <ShieldCheck className="h-4 w-4 text-primary" />
            Active governance policies
          </div>
        </header>
        <div className="divide-y">
          {data.items.map((item) => (
            <article
              key={item.actionId}
              className="grid gap-4 p-4 lg:grid-cols-[1.35fr_.7fr_.9fr]"
            >
              <div>
                <div className="text-sm font-semibold">{item.title}</div>
                <div className="mt-1 text-[10px] text-muted-foreground">
                  Owner {item.owner} · State {item.state} · Priority {item.priority}
                </div>
                <p className="mt-2 text-xs text-muted-foreground">{item.governance.rationale}</p>
              </div>
              <div className="rounded-xl border p-3">
                <div className="text-[9px] uppercase tracking-wider text-muted-foreground">Policy</div>
                <div className="mt-1 text-sm font-bold capitalize">{item.governance.policyTier}</div>
                <div className="mt-1 text-[10px] text-muted-foreground">
                  Approval: {item.governance.approvalRole}
                </div>
              </div>
              <div className="rounded-xl border p-3">
                <div className="flex items-center gap-2 text-xs font-semibold">
                  {item.governance.escalationLevel > 0 ? (
                    <Siren className="h-3.5 w-3.5 text-destructive" />
                  ) : (
                    <CheckCircle2 className="h-3.5 w-3.5" />
                  )}
                  {item.governance.governanceState}
                </div>
                <div className="mt-2 text-[10px] text-muted-foreground">
                  Escalation L{item.governance.escalationLevel} · SLA policy {item.governance.policySlaHours}h
                </div>
                {item.governance.approvalRequired && (
                  <div className="mt-2 inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[9px]">
                    <AlertTriangle className="h-3 w-3" />
                    Approval gate
                  </div>
                )}
              </div>
            </article>
          ))}
          {!data.items.length && (
            <div className="p-10 text-center text-sm text-muted-foreground">No governed actions yet.</div>
          )}
        </div>
      </section>

      <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
        <Clock3 className="h-3.5 w-3.5 text-primary" />
        Governance is derived from live risk, priority and SLA state.
      </div>
    </div>
  )
}
