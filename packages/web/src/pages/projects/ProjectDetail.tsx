import { useMemo } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Activity, AlertTriangle, ArrowRight, Bug, FileText, FolderKanban, Play, Server, ShieldCheck, Target, TrendingUp } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { cn } from '@/utils/cn'

const tabs = [
  ['overview', 'Overview', FolderKanban], ['assets', 'Assets', Server], ['validations', 'Validations', Activity],
  ['findings', 'Findings', Bug], ['evidence', 'Evidence', FileText], ['compliance', 'Compliance', ShieldCheck],
  ['posture', 'Posture', TrendingUp],
] as const

const num = (value: unknown, fallback = 0) => typeof value === 'number' ? value : Number(value || fallback)

export const ProjectDetail = () => {
  const { id } = useParams<{ id: string }>()
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['project-workspace', id],
    queryFn: () => apiHelpers.get<any>(`/projects/${id}`),
    enabled: !!id,
  })

  const project = data?.project ?? data
  const assets = data?.assets ?? project?.assets ?? []
  const findings = data?.findings ?? project?.findings ?? []
  const validations = data?.validations ?? project?.validations ?? []
  const score = num(project?.security_score ?? project?.score, 0)
  const critical = findings.filter((f: any) => f.severity === 'critical').length
  const high = findings.filter((f: any) => f.severity === 'high').length
  const risk = critical > 0 ? 'Critical attention' : high > 0 ? 'Elevated risk' : 'No elevated findings'

  const riskBars = useMemo(() => {
    const counts = ['critical', 'high', 'medium', 'low', 'informational'].map(s => findings.filter((f: any) => f.severity === s).length)
    const max = Math.max(...counts, 1)
    return counts.map((count, i) => ({ label: ['Critical', 'High', 'Medium', 'Low', 'Info'][i], count, width: `${Math.max(4, count / max * 100)}%` }))
  }, [findings])

  if (isLoading) return <div className="space-y-5 animate-pulse"><div className="h-28 rounded-2xl bg-muted" /><div className="grid md:grid-cols-5 gap-3">{[1,2,3,4,5].map(i => <div key={i} className="h-24 rounded-xl bg-muted" />)}</div><div className="h-72 rounded-2xl bg-muted" /></div>

  if (isError || !project) return <div className="rounded-2xl border bg-card p-10 text-center"><AlertTriangle className="mx-auto h-8 w-8 text-amber-500" /><h2 className="mt-3 font-semibold">Unable to load project workspace</h2><p className="mt-1 text-sm text-muted-foreground">The project could not be retrieved from the API.</p><button onClick={() => refetch()} className="mt-5 rounded-lg bg-primary px-4 py-2 text-sm text-primary-foreground">Retry</button></div>

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2 text-sm text-muted-foreground"><Link to="/projects" className="hover:text-foreground">Projects</Link><span>/</span><span>{project.name || id}</span></div>

      <section className="rounded-2xl border bg-card overflow-hidden">
        <div className="p-5 md:p-6 flex flex-col lg:flex-row lg:items-end lg:justify-between gap-5">
          <div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground uppercase tracking-wider"><Target className="h-3.5 w-3.5" /> Security workspace</div>
            <h1 className="mt-2 text-2xl md:text-3xl font-bold tracking-tight">{project.name || id}</h1>
            <p className="mt-1 text-sm text-muted-foreground">{project.description || 'Project security validation workspace'}</p>
            <div className="mt-4 flex flex-wrap gap-2 text-xs"><span className="rounded-full border px-2.5 py-1">Owner · {project.owner_name || project.owner || 'Unassigned'}</span><span className="rounded-full border px-2.5 py-1">Environment · {project.environment || '—'}</span><span className="rounded-full border px-2.5 py-1">Status · {project.status || 'active'}</span></div>
          </div>
          <div className="flex gap-2"><Link to="/validations/new" className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground"><Play className="h-4 w-4" /> Run Validation</Link><Link to="/assets" className="inline-flex items-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium hover:bg-accent"><Server className="h-4 w-4" /> Add Asset</Link></div>
        </div>
        <nav className="border-t overflow-x-auto"><div className="flex min-w-max px-3">{tabs.map(([key, label, Icon]) => <Link key={key} to={`/projects/${id}?tab=${key}`} className="px-3.5 py-3 text-xs font-medium text-muted-foreground hover:text-foreground"> <Icon className="inline h-3.5 w-3.5 mr-1.5" />{label}</Link>)}</div></nav>
      </section>

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        {[['Security Score', score ? `${score}/100` : '—', score >= 80 ? 'Healthy' : score ? 'Needs attention' : 'No score'], ['Critical', critical, critical ? 'Immediate attention' : 'Clear'], ['High', high, high ? 'Elevated' : 'Clear'], ['Assets', assets.length, 'Tracked assets'], ['Validations', validations.length, 'Validation history']].map(([label, value, hint]) => <div key={String(label)} className="rounded-xl border bg-card p-4"><div className="text-xs text-muted-foreground">{label}</div><div className="mt-2 text-2xl font-bold">{value}</div><div className={cn('mt-1 text-[11px]', String(label) === 'Critical' && critical ? 'text-red-500' : 'text-muted-foreground')}>{hint}</div></div>)}
      </div>

      <div className="grid lg:grid-cols-5 gap-4">
        <section className="lg:col-span-3 rounded-2xl border bg-card p-5"><div className="flex items-center justify-between"><div><h2 className="font-semibold">Risk exposure</h2><p className="text-xs text-muted-foreground mt-1">Current findings by severity</p></div><span className="text-xs rounded-full border px-2 py-1">{risk}</span></div><div className="mt-6 space-y-4">{riskBars.map(r => <div key={r.label} className="grid grid-cols-[80px_1fr_30px] items-center gap-3 text-xs"><span className="text-muted-foreground">{r.label}</span><div className="h-2 rounded-full bg-muted overflow-hidden"><div className="h-full rounded-full bg-primary transition-all" style={{ width: r.width }} /></div><span className="text-right font-medium">{r.count}</span></div>)}</div></section>
        <section className="lg:col-span-2 rounded-2xl border bg-card p-5"><h2 className="font-semibold">Validation activity</h2><p className="text-xs text-muted-foreground mt-1">Recent execution state</p><div className="mt-5 space-y-4">{validations.slice(0, 4).map((v: any, index: number) => <div key={v.id || index} className="flex gap-3"><div className="mt-1 h-2.5 w-2.5 rounded-full bg-primary ring-4 ring-primary/10 shrink-0" /><div className="min-w-0 flex-1"><div className="flex justify-between gap-2"><span className="text-sm font-medium truncate">{v.name || v.profile || `Validation ${v.id}`}</span><span className="text-[11px] text-muted-foreground">{v.status || '—'}</span></div><div className="text-xs text-muted-foreground mt-1">{v.created_at ? new Date(v.created_at).toLocaleString() : '—'}</div></div></div>)}{!validations.length && <div className="rounded-xl border border-dashed p-6 text-center text-xs text-muted-foreground">No validations recorded yet.</div>}</div></section>
      </div>

      <section className="rounded-2xl border bg-card overflow-hidden"><div className="p-5 border-b flex items-center justify-between"><div><h2 className="font-semibold">Critical attention</h2><p className="text-xs text-muted-foreground mt-1">Prioritized findings requiring investigation</p></div><Link to="/vulnerabilities" className="text-xs text-primary hover:underline">View all <ArrowRight className="inline h-3 w-3" /></Link></div><div className="divide-y">{findings.filter((f: any) => ['critical', 'high'].includes(f.severity)).slice(0, 5).map((f: any) => <Link key={f.id} to={`/vulnerabilities/${f.id}`} className="flex flex-col md:flex-row md:items-center gap-3 p-4 hover:bg-muted/20"><span className={cn('w-fit rounded px-2 py-1 text-[11px] font-semibold uppercase', f.severity === 'critical' ? 'bg-red-600 text-white' : 'bg-orange-500 text-white')}>{f.severity}</span><div className="flex-1 min-w-0"><div className="font-medium truncate">{f.title || `Finding ${f.id}`}</div><div className="text-xs text-muted-foreground mt-1 font-mono">{f.asset || 'Unknown asset'} · CVSS {f.cvss ?? '—'}</div></div><span className="text-xs text-muted-foreground">Confidence {f.confidence ?? '—'}%</span><ArrowRight className="h-4 w-4 text-muted-foreground" /></Link>)}{!findings.some((f: any) => ['critical', 'high'].includes(f.severity)) && <div className="p-10 text-center text-sm text-muted-foreground"><ShieldCheck className="mx-auto h-7 w-7 mb-2" />No critical or high findings in this project.</div>}</div></section>
    </div>
  )
}
