import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, AlertTriangle, CheckCircle2, FlaskConical, Loader2, Play, RefreshCw, ShieldCheck } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { z } from 'zod'
import { apiHelpers } from '@/services/api'
import { GovernedCapabilityExecutionSchema, apiContractPaths } from '@/contracts/api'
import { useLanguageStore } from '@/stores/languageStore'

const CredentialOptionSchema = z.object({
  credential_ref: z.string().uuid(),
  name: z.string().min(1),
  kind: z.string().min(1),
  identity_ref: z.string().min(1),
  version: z.number().int().positive(),
}).strict()

const CredentialOptionsSchema = z.object({
  contract_version: z.literal('aegis.web-labs-credential-options.v1'),
  project_ref: z.string().uuid(),
  asset_ref: z.string().uuid(),
  lab_ref: z.literal('bac-orders-v1'),
  identity_refs: z.array(z.string()).length(2),
  options: z.array(CredentialOptionSchema),
}).strict()

const RequirementSchema = z.object({
  id: z.string(),
  state: z.enum(['ready', 'blocked', 'unverified']),
  observed_state: z.string(),
  message_ar: z.string(),
  suggested_action_ar: z.string(),
}).strict()

const BlockerSchema = z.object({
  code: z.string(),
  requirement_ref: z.string(),
  observed_state: z.string(),
  message_ar: z.string(),
  suggested_action_ar: z.string(),
}).strict()

const ReadinessSchema = z.object({
  contract_version: z.literal('aegis.web-labs-readiness.v1'),
  project_ref: z.string().uuid(),
  asset_ref: z.string().uuid(),
  lab_ref: z.literal('bac-orders-v1'),
  fixture_revision: z.string().length(64),
  methodology_refs: z.array(z.string()),
  depth: z.string(),
  preview_only: z.literal(true),
  execution_ready: z.boolean(),
  metadata_ready: z.boolean(),
  authorization_ref: z.string().nullable(),
  provider: z.object({ state: z.string(), decision_ref: z.string().nullable() }).strict(),
  credential_metadata: z.array(z.object({
    credential_ref: z.string(),
    identity_ref: z.string().nullable(),
    state: z.string(),
    version: z.number().int().nullable(),
    message_ar: z.string(),
  }).strict()),
  supported_operations: z.array(z.string()),
  capabilities: z.array(z.object({
    id: z.string(),
    registered: z.boolean(),
    runtime_verified: z.literal(false),
  }).strict()),
  requirements: z.array(RequirementSchema),
  blockers: z.array(BlockerSchema),
  explanation_ar: z.string(),
}).strict()

type Project = { id: string; name: string }
type Asset = { id: string; project_id: string; name: string; type: string; is_active: boolean }
type Depth = 'quick' | 'standard' | 'deep' | 'comprehensive'

export const WebLabsPage = () => {
  const t = useLanguageStore((s) => s.t)
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [projectId, setProjectId] = useState('')
  const [assetId, setAssetId] = useState('')
  const [depth, setDepth] = useState<Depth>('standard')
  const [selected, setSelected] = useState<Record<string, string>>({})

  const projects = useQuery<Project[]>({
    queryKey: ['web-labs-projects'],
    queryFn: () => apiHelpers.get<Project[]>('/projects/'),
  })
  const assets = useQuery<Asset[]>({
    queryKey: ['web-labs-assets', projectId],
    queryFn: () => apiHelpers.get<Asset[]>('/assets/', { params: { project_id: projectId } }),
    enabled: Boolean(projectId),
  })
  const options = useQuery({
    queryKey: ['web-labs-credential-options', projectId, assetId],
    queryFn: async () => CredentialOptionsSchema.parse(await apiHelpers.get<unknown>(
      '/web-labs/credential-options',
      { params: { project_id: projectId, asset_id: assetId, lab_definition_id: 'bac-orders-v1' } },
    )),
    enabled: Boolean(projectId && assetId),
  })

  const identities = options.data?.identity_refs || ['alice', 'bob']
  const selectedRefs = identities.map((identity) => selected[identity]).filter(Boolean)
  const hasBothIdentities = identities.every((identity) => Boolean(selected[identity]))

  const readiness = useQuery({
    queryKey: ['web-labs-readiness', projectId, assetId, depth, ...selectedRefs],
    queryFn: async () => ReadinessSchema.parse(await apiHelpers.post<unknown>('/web-labs/prepare', {
      project_id: projectId,
      asset_id: assetId,
      lab_definition_id: 'bac-orders-v1',
      credential_refs: selectedRefs,
      depth,
    })),
    enabled: Boolean(projectId && assetId && hasBothIdentities),
  })

  const capability = readiness.data?.capabilities.find((item) => item.id === 'burp.mcp.gateway')
  const canCollect = Boolean(
    readiness.data?.metadata_ready
    && readiness.data.provider.decision_ref
    && capability?.registered
    && readiness.data.supported_operations.includes('burp.http_request')
    && hasBothIdentities
  )

  const execute = useMutation({
    mutationFn: async () => {
      const preview = readiness.data
      if (!preview?.provider.decision_ref || !canCollect) throw new Error(t('Web Lab metadata is not ready'))
      const raw = await apiHelpers.post<unknown>(
        apiContractPaths.capabilityExecute('burp.mcp.gateway'),
        {
          project_id: projectId,
          asset_id: assetId,
          depth,
          options: {
            provider_decision_ref: preview.provider.decision_ref,
            lab_definition_id: 'bac-orders-v1',
            mode: 'lab_sequence',
          },
          credential_refs: selectedRefs,
          idempotency_key: 'web-lab-ui-' + crypto.randomUUID(),
          correlation_id: 'web-lab-ui-corr-' + crypto.randomUUID(),
        },
      )
      return GovernedCapabilityExecutionSchema.parse(raw)
    },
    onSuccess: async (result) => {
      await qc.invalidateQueries({ queryKey: ['scans'] })
      toast.success(t('Web Lab observation run queued') + ' · ' + result.scan.id)
      navigate('/scan/' + result.scan.id + '/progress')
    },
    onError: (error: any) => {
      const detail = error?.response?.data?.detail
      toast.error(
        (typeof detail === 'object' && detail?.message_ar)
        || (typeof detail === 'string' && detail)
        || error?.message
        || t('Unable to start Web Lab observation run'),
      )
    },
  })

  const webAssets = useMemo(
    () => (assets.data || []).filter((asset) => asset.is_active && ['website', 'api_endpoint'].includes(asset.type)),
    [assets.data],
  )

  const resetScope = (nextProject: string) => {
    setProjectId(nextProject)
    setAssetId('')
    setSelected({})
  }

  return (
    <div className="space-y-6 pb-10">
      <section className="enterprise-card rounded-3xl p-6 md:p-8">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.16em] text-primary">
              <FlaskConical className="h-4 w-4" /> {t('Web Labs')}
            </div>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight">{t('Governed Web Lab')}</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
              {t('Select a project, web asset and the two project-scoped identities. AegisScan previews readiness without dispatching traffic, then schedules only the sealed BAC observation recipe through the existing governed capability path.')}
            </p>
          </div>
          <div className="rounded-2xl border bg-background/30 px-4 py-3 text-xs text-muted-foreground">
            <div className="font-semibold text-foreground">WSTG-v42-ATHZ-04 · bac-orders-v1</div>
            <div className="mt-1">{t('Browser lifecycle authority remains host-governed and is never exposed to this page.')}</div>
          </div>
        </div>
      </section>

      <section className="enterprise-card rounded-2xl p-5">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <label>
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{t('Project')}</span>
            <select value={projectId} onChange={(e) => resetScope(e.target.value)} className="mt-2 h-11 w-full rounded-xl border bg-background px-3 text-sm">
              <option value="">{t('Select project')}</option>
              {(projects.data || []).map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
            </select>
          </label>
          <label>
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{t('Asset')}</span>
            <select
              value={assetId}
              onChange={(e) => { setAssetId(e.target.value); setSelected({}) }}
              disabled={!projectId}
              className="mt-2 h-11 w-full rounded-xl border bg-background px-3 text-sm"
            >
              <option value="">{t('Select web asset')}</option>
              {webAssets.map((asset) => <option key={asset.id} value={asset.id}>{asset.name} · {asset.type}</option>)}
            </select>
          </label>
          <label>
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{t('Depth')}</span>
            <select value={depth} onChange={(e) => setDepth(e.target.value as Depth)} className="mt-2 h-11 w-full rounded-xl border bg-background px-3 text-sm">
              {(['quick', 'standard', 'deep', 'comprehensive'] as const).map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
          <div className="flex items-end">
            <button
              type="button"
              onClick={() => { void options.refetch(); if (hasBothIdentities) void readiness.refetch() }}
              disabled={!assetId}
              className="inline-flex h-11 w-full items-center justify-center gap-2 rounded-xl border px-4 text-sm font-semibold disabled:opacity-50"
            >
              <RefreshCw className={'h-4 w-4 ' + ((options.isFetching || readiness.isFetching) ? 'animate-spin' : '')} />
              {t('Refresh readiness')}
            </button>
          </div>
        </div>
      </section>

      {assetId && (
        <section className="grid gap-4 lg:grid-cols-2">
          {identities.map((identity) => {
            const candidates = (options.data?.options || []).filter((item) => item.identity_ref === identity)
            return (
              <div key={identity} className="enterprise-card rounded-2xl p-5">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-primary" />
                  <div className="font-semibold">{t('Target identity')} · {identity}</div>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{t('Only active credentials already bound to this asset origin are listed. Secret material is never returned.')}</p>
                <select
                  value={selected[identity] || ''}
                  onChange={(e) => setSelected((current) => ({ ...current, [identity]: e.target.value }))}
                  className="mt-4 h-11 w-full rounded-xl border bg-background px-3 text-sm"
                >
                  <option value="">{t('Select credential')}</option>
                  {candidates.map((item) => <option key={item.credential_ref} value={item.credential_ref}>{item.name} · {item.kind} · v{item.version}</option>)}
                </select>
                {!options.isLoading && candidates.length === 0 && <div className="mt-3 text-xs text-amber-600">{t('No matching project credential is available for this identity and asset origin.')}</div>}
              </div>
            )
          })}
        </section>
      )}

      {readiness.data && (
        <>
          <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {[
              [t('Metadata'), readiness.data.metadata_ready ? t('Ready') : t('Blocked')],
              [t('Provider'), readiness.data.provider.state],
              [t('Methodology'), readiness.data.methodology_refs.join(', ')],
              [t('Fixture revision'), readiness.data.fixture_revision.slice(0, 16) + '…'],
            ].map(([label, value]) => (
              <div key={label} className="enterprise-card rounded-2xl p-4">
                <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">{label}</div>
                <div className="mt-2 break-all text-sm font-semibold">{value}</div>
              </div>
            ))}
          </section>

          <section className="enterprise-card rounded-2xl p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-semibold">{t('Readiness requirements')}</h2>
                <p className="mt-1 text-xs text-muted-foreground">{readiness.data.explanation_ar}</p>
              </div>
              <span className={'rounded-full border px-3 py-1 text-xs font-semibold ' + (canCollect ? 'bg-emerald-500/10 text-emerald-600' : 'bg-amber-500/10 text-amber-600')}>
                {canCollect ? t('Observation run ready') : t('Action required')}
              </span>
            </div>
            <div className="mt-4 grid gap-3 lg:grid-cols-2">
              {readiness.data.requirements.map((item) => (
                <div key={item.id} className="rounded-xl border bg-background/30 p-4">
                  <div className="flex items-start gap-3">
                    {item.state === 'ready'
                      ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
                      : <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" />}
                    <div>
                      <div className="text-xs font-semibold">{item.id} · {item.observed_state}</div>
                      <p className="mt-1 text-xs leading-5 text-muted-foreground">{item.message_ar}</p>
                      {item.state !== 'ready' && <p className="mt-2 text-xs leading-5 text-primary">{item.suggested_action_ar}</p>}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="enterprise-card rounded-2xl p-5">
            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
              <div>
                <div className="flex items-center gap-2 font-semibold"><Activity className="h-4 w-4 text-primary" />{t('Governed observation run')}</div>
                <p className="mt-1 max-w-3xl text-xs leading-5 text-muted-foreground">
                  {t('This action collects the sealed Alice/Bob BAC observations. It does not claim a solved lab or verified live fixture; verified lifecycle evidence remains a separate host-governed acceptance path.')}
                </p>
              </div>
              <button
                type="button"
                disabled={!canCollect || execute.isPending}
                onClick={() => execute.mutate()}
                className="inline-flex min-w-52 items-center justify-center gap-2 rounded-xl bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground disabled:opacity-50"
              >
                {execute.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                {t('Collect BAC observations')}
              </button>
            </div>
          </section>
        </>
      )}
    </div>
  )
}
