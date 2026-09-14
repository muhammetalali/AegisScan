import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, AlertCircle, ArrowUpRight, Play, Plus, RefreshCw, Trash2, X } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { CapabilityPlanSchema, GovernedCapabilityExecutionSchema, apiContractPaths, type CapabilityPlan } from '@/contracts/api'
import { useLanguageStore } from '@/stores/languageStore'
import { toast } from 'sonner'
import { cn } from '@/utils/cn'

type Scan = {
  id: string
  project_id: string
  name: string
  scan_type: string
  status: string
  progress?: number | null
  current_phase?: string | null
  security_score?: number | null
  risk_level?: string | null
  findings_count?: number | null
  created_at: string
  completed_at?: string | null
}
type Project = { id: string; name: string }
type Asset = {
  id: string
  project_id: string
  name: string
  type: string
  configuration: Record<string, unknown>
  is_active: boolean
}

export const ScanPage = () => {
  const t = useLanguageStore((s) => s.t)
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [projectId, setProjectId] = useState('')
  const [assetId, setAssetId] = useState('')
  const [capabilityId, setCapabilityId] = useState('')
  const [depth, setDepth] = useState<'quick' | 'standard' | 'deep' | 'comprehensive'>('standard')
  const [busy, setBusy] = useState(false)

  const scans = useQuery<Scan[]>({
    queryKey: ['scans'],
    queryFn: () => apiHelpers.get<Scan[]>('/scans/?limit=100'),
  })
  const projects = useQuery<Project[]>({
    queryKey: ['projects'],
    queryFn: () => apiHelpers.get<Project[]>('/projects/'),
  })
  const assets = useQuery<Asset[]>({
    queryKey: ['assets-scan-picker', projectId],
    queryFn: () => apiHelpers.get<Asset[]>('/assets/', { params: { project_id: projectId } }),
    enabled: Boolean(projectId),
  })
  const capabilityPlan = useQuery<CapabilityPlan>({
    queryKey: ['capability-plan', projectId, assetId, depth],
    queryFn: async () => CapabilityPlanSchema.parse(
      await apiHelpers.get<unknown>(apiContractPaths.capabilityPlan(assetId), {
        params: { project_id: projectId, depth },
      }),
    ),
    enabled: Boolean(projectId && assetId),
    staleTime: 30_000,
  })

  const readyCapabilities = (capabilityPlan.data?.plan || []).filter((item) => item.execution_ready)

  const create = async () => {
    if (!projectId || !assetId || !capabilityId) return
    setBusy(true)
    try {
      const idempotencyKey = `ui-${crypto.randomUUID()}`
      const correlationId = `ui-corr-${crypto.randomUUID()}`
      const raw = await apiHelpers.post<unknown>(apiContractPaths.capabilityExecute(capabilityId), {
        project_id: projectId,
        asset_id: assetId,
        depth,
        options: {},
        credential_refs: [],
        idempotency_key: idempotencyKey,
        correlation_id: correlationId,
      })
      const result = GovernedCapabilityExecutionSchema.parse(raw)
      await qc.invalidateQueries({ queryKey: ['scans'] })
      setOpen(false)
      setCapabilityId('')
      toast.success(
        `${t('Scan queued')} · ${result.scan.id} · ${result.execution_contract.runner_profile}`,
      )
    } catch (error: any) {
      toast.error(error?.response?.data?.detail || error?.message || t('Unable to create scan'))
    } finally {
      setBusy(false)
    }
  }

  const remove = async (id: string) => {
    if (!window.confirm(t('Delete this scan?'))) return
    try {
      await apiHelpers.delete(`/scans/${id}`)
      await qc.invalidateQueries({ queryKey: ['scans'] })
      toast.success(t('Scan deleted'))
    } catch (error: any) {
      toast.error(error?.response?.data?.detail || error?.message || t('Unable to delete scan'))
    }
  }

  return (
    <div className="space-y-6 pb-10">
      <section className="enterprise-card rounded-3xl p-6 md:p-8">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.16em] text-primary">
              <Activity className="h-4 w-4" />
              {t('Validations')}
            </div>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight">{t('Scan registry')}</h1>
            <p className="mt-2 text-sm text-muted-foreground">
              {t('Every execution shown here is a persisted Scan and engine execution from the platform backend.')}
            </p>
          </div>
          <div className="flex gap-2">
            <button type="button" onClick={() => scans.refetch()} className="rounded-xl border p-2.5">
              <RefreshCw className={cn('h-4 w-4', scans.isFetching && 'animate-spin')} />
            </button>
            <button
              type="button"
              onClick={() => setOpen(true)}
              className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground"
            >
              <Plus className="h-4 w-4" />
              {t('New scan')}
            </button>
          </div>
        </div>
      </section>

      {scans.isLoading ? (
        <div className="enterprise-card p-12 text-center text-sm text-muted-foreground">{t('Loading...')}</div>
      ) : scans.isError ? (
        <div className="enterprise-card p-12 text-center">
          <AlertCircle className="mx-auto h-8 w-8 text-destructive" />
          <p className="mt-3 font-medium">{t('Unable to load scans')}</p>
          <button onClick={() => scans.refetch()} className="mt-4 rounded-xl border px-4 py-2 text-sm">
            {t('Retry')}
          </button>
        </div>
      ) : (
        <section className="enterprise-card overflow-hidden rounded-2xl">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1080px] text-sm">
              <thead>
                <tr className="border-b bg-muted/20 text-xs text-muted-foreground">
                  {['Scan', 'Type', 'Status', 'Progress', 'Security score', 'Risk', 'Findings', 'Created', 'Actions'].map((column) => (
                    <th key={column} className="px-4 py-3 text-start">
                      {t(column)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {!scans.data?.length ? (
                  <tr>
                    <td colSpan={9} className="px-6 py-16 text-center">
                      <Activity className="mx-auto h-7 w-7 text-muted-foreground" />
                      <p className="mt-3 font-medium">{t('No scans available')}</p>
                    </td>
                  </tr>
                ) : (
                  scans.data.map((scan) => (
                    <tr key={scan.id} className="border-b last:border-0 hover:bg-muted/20">
                      <td className="px-4 py-4">
                        <Link to={`/scan/${scan.id}/results`} className="font-semibold hover:text-primary">
                          {scan.name}
                        </Link>
                        <div className="mt-1 font-mono text-[10px] text-muted-foreground">{scan.id}</div>
                      </td>
                      <td className="px-4 py-4">{scan.scan_type}</td>
                      <td className="px-4 py-4">
                        <span className="rounded-full border bg-muted/30 px-2 py-1 text-[11px]">{scan.status}</span>
                      </td>
                      <td className="px-4 py-4">
                        {scan.progress == null ? '—' : `${scan.progress}%`}
                        {scan.current_phase ? <div className="text-[10px] text-muted-foreground">{scan.current_phase}</div> : null}
                      </td>
                      <td className="px-4 py-4">{scan.security_score == null ? '—' : scan.security_score}</td>
                      <td className="px-4 py-4">{scan.risk_level || '—'}</td>
                      <td className="px-4 py-4">{scan.findings_count == null ? '—' : scan.findings_count}</td>
                      <td className="px-4 py-4 text-xs text-muted-foreground">{new Date(scan.created_at).toLocaleString()}</td>
                      <td className="px-4 py-4">
                        <div className="flex gap-1">
                          <Link to={`/scan/${scan.id}/results`} className="rounded-lg p-2 hover:bg-accent" title={t('Open')}>
                            <ArrowUpRight className="h-4 w-4" />
                          </Link>
                          <Link to={`/scan/${scan.id}/progress`} className="rounded-lg p-2 text-primary hover:bg-primary/10" title={t('Progress')}>
                            <Play className="h-4 w-4" />
                          </Link>
                          <button
                            type="button"
                            onClick={() => remove(scan.id)}
                            className="rounded-lg p-2 text-destructive hover:bg-destructive/10"
                            title={t('Delete')}
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {open && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/55 p-4 backdrop-blur-sm">
          <div className="enterprise-card w-full max-w-xl rounded-3xl p-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-semibold">{t('New scan')}</h2>
                <p className="mt-1 text-xs text-muted-foreground">
                  {t('Execution is created server-side and remains subject to authorization and scope controls.')}
                </p>
              </div>
              <button onClick={() => setOpen(false)} className="rounded-xl border p-2">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="mt-6 space-y-4">
              <label className="block">
                <span className="text-sm font-medium">{t('Project')}</span>
                <select
                  value={projectId}
                  onChange={(event) => {
                    setProjectId(event.target.value)
                    setAssetId('')
                    setCapabilityId('')
                  }}
                  className="mt-2 h-11 w-full rounded-xl border bg-background px-3 text-sm"
                >
                  <option value="">{t('Select project')}</option>
                  {(projects.data || []).map((project) => (
                    <option key={project.id} value={project.id}>
                      {project.name}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block">
                <span className="text-sm font-medium">{t('Asset')}</span>
                <select
                  value={assetId}
                  onChange={(event) => {
                    setAssetId(event.target.value)
                    setCapabilityId('')
                  }}
                  disabled={!projectId}
                  className="mt-2 h-11 w-full rounded-xl border bg-background px-3 text-sm"
                >
                  <option value="">{t('Select asset')}</option>
                  {(assets.data || [])
                    .filter((asset) => asset.is_active)
                    .map((asset) => (
                      <option key={asset.id} value={asset.id}>
                        {asset.name} · {asset.type}
                      </option>
                    ))}
                </select>
              </label>
              <label className="block">
                <span className="text-sm font-medium">{t('Depth')}</span>
                <select
                  value={depth}
                  onChange={(event) => {
                    setDepth(event.target.value as 'quick' | 'standard' | 'deep' | 'comprehensive')
                    setCapabilityId('')
                  }}
                  className="mt-2 h-11 w-full rounded-xl border bg-background px-3 text-sm"
                >
                  {(['quick', 'standard', 'deep', 'comprehensive'] as const).map((value) => (
                    <option key={value} value={value}>{value}</option>
                  ))}
                </select>
              </label>
              <label className="block">
                <span className="text-sm font-medium">{t('Capability')}</span>
                <select
                  value={capabilityId}
                  onChange={(event) => setCapabilityId(event.target.value)}
                  disabled={!assetId || capabilityPlan.isLoading}
                  className="mt-2 h-11 w-full rounded-xl border bg-background px-3 text-sm"
                >
                  <option value="">
                    {capabilityPlan.isLoading ? t('Loading...') : t('Select capability')}
                  </option>
                  {readyCapabilities.map((item) => (
                    <option key={item.capability_id} value={item.capability_id}>
                      {item.capability_id} · {item.risk} · {item.tool}
                    </option>
                  ))}
                </select>
                {assetId && capabilityPlan.isSuccess && readyCapabilities.length === 0 ? (
                  <p className="mt-2 text-xs text-muted-foreground">
                    {t('No governed capability is execution-ready for this asset and depth.')}
                  </p>
                ) : null}
              </label>
            </div>
            <div className="mt-7 flex justify-end gap-2">
              <button onClick={() => setOpen(false)} className="rounded-xl border px-4 py-2.5 text-sm">
                {t('Cancel')}
              </button>
              <button
                onClick={create}
                disabled={busy || !projectId || !assetId || !capabilityId}
                className="rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-50"
              >
                {busy ? t('Creating…') : t('Run capability')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
