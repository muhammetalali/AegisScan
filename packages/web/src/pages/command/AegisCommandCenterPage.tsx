import { useMemo } from 'react'
import { AlertTriangle, ArrowRight, CheckCircle2, RefreshCw, ShieldCheck, Target, Zap } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { apiHelpers } from '@/services/api'
import AegisCommandCenter, { type AegisCommandSignal } from '@/components/command/AegisCommandCenter'

const actionLinks = [
  { label: 'Investigate', to: '/assurance/triage', icon: Target },
  { label: 'Decide', to: '/assurance/decisions', icon: ShieldCheck },
  { label: 'Execute', to: '/assurance/actions', icon: Zap },
  { label: 'Verify', to: '/assurance/continuous', icon: CheckCircle2 },
]

export function AegisCommandCenterPage() {
  const summaryQuery = useQuery({ queryKey: ['command-center-summary'], queryFn: () => apiHelpers.get<any>('/dashboard/summary') })
  const riskQuery = useQuery({ queryKey: ['command-center-risk'], queryFn: () => apiHelpers.get<any>('/dashboard/risk-distribution') })
  const recentQuery = useQuery({ queryKey: ['command-center-recent'], queryFn: () => apiHelpers.get<any>('/dashboard/recent-validations?limit=5') })

  const summary = summaryQuery.data
  const risk = riskQuery.data
  const recent = Array.isArray(recentQuery.data) ? recentQuery.data : []
  const posture = typeof summary?.security_score === 'number' ? summary.security_score : 0

  const signals = useMemo<AegisCommandSignal[]>(() => {
    const result: AegisCommandSignal[] = []
    const critical = Number(risk?.critical ?? summary?.critical ?? 0)
    const high = Number(risk?.high ?? summary?.high ?? 0)
    if (critical > 0) result.push({ id: 'critical-findings', title: `${critical} critical finding${critical === 1 ? '' : 's'} require attention`, detail: 'Current risk telemetry indicates immediate investigation is recommended.', severity: 'critical', action: 'Investigate' })
    if (high > 0) result.push({ id: 'high-findings', title: `${high} high-severity finding${high === 1 ? '' : 's'} remain`, detail: 'Prioritize remediation and re-validation for high-impact exposure.', severity: 'high', action: 'Review' })
    const latest = recent[0]
    if (latest) result.push({ id: `validation-${latest.id ?? latest.validation_id ?? 'latest'}`, title: `Latest validation: ${String(latest.status ?? 'unknown')}`, detail: String(latest.target_value ?? latest.target ?? latest.project_name ?? 'Recent validation activity'), severity: latest.status === 'completed' || latest.status === 'success' ? 'success' : 'medium', action: 'View' })
    return result
  }, [risk, summary, recent])

  const loading = summaryQuery.isLoading || riskQuery.isLoading || recentQuery.isLoading
  const error = summaryQuery.error || riskQuery.error || recentQuery.error

  if (loading) return <div className="aegis-surface rounded-2xl border border-white/10 p-10 text-center text-sm text-slate-400">Loading command intelligence…</div>
  if (error) return <div className="aegis-surface rounded-2xl border border-red-500/20 p-10 text-center"><AlertTriangle className="mx-auto h-8 w-8 text-red-400" /><h1 className="mt-3 font-semibold text-white">Command intelligence unavailable</h1><p className="mt-1 text-sm text-slate-400">Live dashboard data could not be loaded.</p><button type="button" onClick={() => { void summaryQuery.refetch(); void riskQuery.refetch(); void recentQuery.refetch() }} className="mt-4 inline-flex items-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-xs font-semibold text-slate-200"><RefreshCw size={14} /> Retry</button></div>

  return <div className="space-y-6">
    <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
      <div><div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300"><ShieldCheck size={15} /> Decision Intelligence</div><h1 className="text-2xl font-semibold tracking-tight text-white lg:text-3xl">Command Center</h1><p className="mt-1 max-w-2xl text-sm text-slate-400">Move from signal to decision, action and verification without leaving the operational context.</p></div>
      <div className="flex flex-wrap gap-2">{actionLinks.map(({ label, to, icon: Icon }) => <Link key={to} to={to} className="aegis-command-surface inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold text-slate-200 hover:text-white"><Icon size={14} />{label}<ArrowRight size={13} /></Link>)}</div>
    </div>
    <AegisCommandCenter posture={posture} delta={0} signals={signals} decisionsRequired={Number(risk?.critical ?? summary?.critical ?? 0)} />
  </div>
}

export default AegisCommandCenterPage
