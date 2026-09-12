import React, { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, ArrowRight, CheckCircle2, ClipboardCheck, FileText, Play, RefreshCw, ShieldAlert } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { apiHelpers } from '@/services/api'

interface Decision {
  decisionId: string; nodeId: string; label: string; urgency: string; risk: number; confidence: number
  conflicts: number; priority: number; executiveImpact: number; recommendedAction: string
  investigationBrief: string; remediationBrief: string; revalidationPlan: string[]
  validationId?: string | null; projectId?: string | null; actionable: boolean; actionabilityReason?: string | null
  decisionSource?: 'risk_correlation' | 'assurance_graph'; riskCorrelationId?: string | null
  riskCorrelationSha256?: string | null; riskAnalysisVersion?: string | null
  riskCorrelationPriority?: string | null; riskCorrelationScore?: number | null; triagePriority?: number
  supportingEvidenceCount?: number; contradictingEvidenceCount?: number; neutralEvidenceCount?: number
}
interface Payload {
  decisions: Decision[]
  summary: { total: number; critical: number; high: number; requiresInvestigation: number; executivePriority: number; actionable: number; correlated?: number }
}

export const SecurityDecisionPage: React.FC = () => {
  const [data, setData] = useState<Payload | null>(null)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState<Decision | null>(null)
  const [creating, setCreating] = useState(false)
  const navigate = useNavigate()
  const load = async () => {
    try { setError(''); setData(await apiHelpers.get<Payload>('/assurance/decision-pack')) }
    catch (e: any) { setError(e?.response?.data?.detail || e?.message || 'Decision pack unavailable') }
  }
  useEffect(() => { void load() }, [])
  const stats = useMemo(() => data?.summary, [data])
  const createAction = async () => {
    if (!selected?.actionable || creating) return
    setCreating(true); setError('')
    try {
      const action = await apiHelpers.post<{ actionId: string }>('/assurance/actions', {
        decision_id: selected.decisionId, owner: 'Security Operations',
        sla_hours: selected.urgency === 'critical' ? 8 : selected.urgency === 'high' ? 24 : 72,
      })
      if (!action.actionId) throw new Error('Remediation action id missing')
      navigate(`/assurance/actions/${action.actionId}`)
    } catch (e: any) { setError(e?.response?.data?.detail || e?.message || 'Unable to create remediation action') }
    finally { setCreating(false) }
  }
  if (error && !data) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Decision pack unavailable</h1><p className="mt-2 text-sm text-muted-foreground">{error}</p><button onClick={() => void load()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold"><RefreshCw className="h-3.5 w-3.5" />Retry</button></div></div>
  if (!data) return <div className="p-8 text-sm opacity-70">Loading live security decisions…</div>
  return <div className="space-y-6 p-6">
    <header><div className="flex items-center gap-2 text-xs uppercase tracking-widest opacity-60"><ShieldAlert size={15} />Decision Intelligence</div><h1 className="mt-2 text-3xl font-semibold">Security Decision Command Center</h1><p className="mt-1 opacity-65">Evidence-backed decisions retain validation, project, and tenant lineage before execution.</p>{error && <p className="mt-2 text-xs text-red-400">{error}</p>}</header>
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">{[['Priority', stats?.executivePriority], ['Critical', stats?.critical], ['High', stats?.high], ['Investigation', stats?.requiresInvestigation], ['Actionable', stats?.actionable], ['Correlated', stats?.correlated], ['Decisions', stats?.total]].map(([label, value]) => <div key={String(label)} className="rounded-xl border p-4"><div className="text-xs opacity-60">{label}</div><div className="mt-1 text-2xl font-semibold">{value}</div></div>)}</div>
    <div className="grid gap-5 lg:grid-cols-[1.4fr_.9fr]">
      <section className="overflow-hidden rounded-2xl border"><div className="border-b p-4 font-medium">Priority decision queue</div>{data.decisions.map((decision, index) => <button key={decision.decisionId} onClick={() => setSelected(decision)} className="w-full border-b p-4 text-left transition last:border-0 hover:bg-black/5"><div className="flex items-center gap-3"><span className="text-xs opacity-50">#{index + 1}</span><div className="flex-1"><div className="flex items-center gap-2 font-medium">{decision.label}<span className={`rounded-full border px-2 py-0.5 text-[9px] uppercase ${decision.actionable ? 'text-emerald-600' : 'text-amber-600'}`}>{decision.actionable ? 'Actionable' : 'Context only'}</span></div><div className="mt-1 text-xs opacity-60">{decision.recommendedAction}</div></div><div className="text-right"><div className="font-semibold">{decision.priority}</div><div className="text-[11px] opacity-50">priority</div></div><ArrowRight size={16} className="opacity-40" /></div><div className="mt-3 flex flex-wrap gap-4 text-[11px] opacity-60"><span>Risk {decision.risk}</span><span>Confidence {decision.confidence}%</span><span>Conflicts {decision.conflicts}</span><span>Impact {decision.executiveImpact}</span>{decision.decisionSource === 'risk_correlation' && <span>Risk v{decision.riskAnalysisVersion}</span>}</div></button>)}</section>
      <aside className="space-y-5 rounded-2xl border p-5">{selected ? <><div><div className="text-xs uppercase tracking-wider opacity-50">Decision brief</div><h2 className="mt-1 text-xl font-semibold">{selected.label}</h2></div><div className="grid grid-cols-3 gap-2">{[['Risk', selected.risk], ['Confidence', `${selected.confidence}%`], ['Priority', selected.priority]].map(([label, value]) => <div key={String(label)} className="rounded-lg border p-3"><div className="text-xs opacity-50">{label}</div><b>{value}</b></div>)}</div>{selected.decisionSource === 'risk_correlation' && <div className="rounded-lg border p-3 text-xs"><div className="font-medium">Risk correlation lineage</div><div className="mt-2 grid grid-cols-2 gap-2 opacity-70"><span>Version {selected.riskAnalysisVersion}</span><span>{selected.riskCorrelationPriority}</span><span>Supporting {selected.supportingEvidenceCount ?? 0}</span><span>Contradicting {selected.contradictingEvidenceCount ?? 0}</span><span>Neutral {selected.neutralEvidenceCount ?? 0}</span><span className="truncate" title={selected.riskCorrelationSha256 || ''}>SHA {selected.riskCorrelationSha256?.slice(0, 12)}…</span></div></div>}<div><div className="flex items-center gap-2 text-xs font-medium"><AlertTriangle size={14} />Investigation</div><p className="mt-2 text-sm opacity-70">{selected.investigationBrief}</p></div><div><div className="flex items-center gap-2 text-xs font-medium"><ClipboardCheck size={14} />Remediation</div><p className="mt-2 text-sm opacity-70">{selected.remediationBrief}</p></div><div><div className="text-xs font-medium">Re-validation plan</div><ul className="mt-2 space-y-2 text-sm opacity-70">{selected.revalidationPlan.map(step => <li key={step} className="flex gap-2"><CheckCircle2 size={15} />{step}</li>)}</ul></div>{!selected.actionable && <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-700">{selected.actionabilityReason}</div>}<div className="grid grid-cols-3 gap-2"><button onClick={() => selected.validationId && navigate(`/validations/${selected.validationId}/results`)} disabled={!selected.validationId} className="rounded-lg border px-3 py-2 text-sm disabled:opacity-40">Investigate</button><button onClick={() => navigate('/reports')} className="rounded-lg border px-3 py-2 text-sm"><FileText size={14} className="mr-1 inline" />Report</button><button onClick={() => void createAction()} disabled={creating || !selected.actionable} className="rounded-lg bg-primary px-3 py-2 text-sm text-primary-foreground disabled:opacity-40"><Play size={14} className="mr-1 inline" />{creating ? 'Creating…' : 'Start action'}</button></div></> : <div className="flex h-full items-center justify-center text-sm opacity-50">Select a decision to inspect its brief.</div>}</aside>
    </div>
  </div>
}
