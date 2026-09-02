import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertCircle, ArrowUpRight, FolderKanban, Plus, Search, ShieldCheck, Sparkles, X } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'
import { Skeleton } from '@/components/ui/skeleton'
import { useLanguageStore } from '@/stores/languageStore'
import { toast } from 'sonner'

type LastValidation = { id: string; name: string; status: string; created_at: string; completed_at?: string | null; security_score?: number | null; risk_level?: string | null }
type Project = {
  id: string
  name: string
  owner?: string | null
  assets?: number
  validations?: number
  findings?: number
  security_score?: number | null
  risk?: string | null
  average_risk_score?: number | null
  last_validation?: LastValidation | null
  status?: string | null
  updated_at?: string
}
type ProjectsResponse = Project[] | { items?: Project[]; results?: Project[]; count?: number }
type ProjectCreateResponse = { id: string; name: string }

const unwrapProjects = (data: ProjectsResponse | undefined): Project[] => Array.isArray(data) ? data : data?.items ?? data?.results ?? []
const riskClass = (risk?: string | null) => {
  switch (risk?.toLowerCase()) {
    case 'critical': return 'border-destructive/30 bg-destructive/10 text-destructive'
    case 'high': return 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400'
    case 'medium': return 'border-yellow-500/30 bg-yellow-500/10 text-yellow-700 dark:text-yellow-400'
    default: return risk ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'border-border bg-muted/20 text-muted-foreground'
  }
}
const scoreClass = (score?: number | null) => score == null ? 'text-muted-foreground' : score >= 80 ? 'text-emerald-600 dark:text-emerald-400' : score >= 60 ? 'text-amber-600 dark:text-amber-400' : 'text-destructive'

export const Projects = () => {
  const t = useLanguageStore(s => s.t)
  const queryClient = useQueryClient()
  const [q, setQ] = useState('')
  const [createOpen, setCreateOpen] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [environment, setEnvironment] = useState('development')
  const [creating, setCreating] = useState(false)
  const { data, isLoading, isError, refetch } = useQuery<ProjectsResponse>({ queryKey: ['projects'], queryFn: () => apiHelpers.get<ProjectsResponse>('/projects/'), staleTime: 30_000 })
  const projects = unwrapProjects(data)
  const items = useMemo(() => { const needle=q.trim().toLowerCase(); return needle ? projects.filter(p => [p.name,p.owner,p.risk,p.status].some(v=>String(v??'').toLowerCase().includes(needle))) : projects }, [projects,q])
  const totalAssets = projects.reduce((sum, project) => sum + (project.assets ?? 0), 0)
  const scoredProjects = projects.filter(project => typeof project.security_score === 'number')
  const averageScore = scoredProjects.length ? Math.round(scoredProjects.reduce((sum, project) => sum + Number(project.security_score), 0) / scoredProjects.length) : null
  const highRisk = projects.filter(project => ['critical','high'].includes(project.risk?.toLowerCase() ?? '')).length

  const createProject = async () => {
    const trimmed = name.trim(); if (!trimmed) return void toast.error(t('Project name is required'))
    setCreating(true)
    try {
      const created = await apiHelpers.post<ProjectCreateResponse>('/projects/', { name: trimmed, description: description.trim(), environment, status: 'active', tags: [], settings: {}, default_scan_config: {} })
      if (!created?.id) throw new Error(t('Project service did not return a project id'))
      await queryClient.invalidateQueries({ queryKey: ['projects'] }); setCreateOpen(false); setName(''); setDescription(''); setEnvironment('development'); toast.success(t('Project created successfully'))
    } catch (error:any) {
      const detail=error?.response?.data?.detail; const message=Array.isArray(detail)?detail.join(', '):typeof detail==='string'?detail:error?.response?.data?.name?.[0]||error?.message; toast.error(message||t('Unable to create project'))
    } finally { setCreating(false) }
  }

  return <div className="space-y-6 pb-10">
    <header className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between"><div className="space-y-2"><div className="inline-flex items-center gap-2 rounded-full border bg-card/80 px-3 py-1 text-xs text-muted-foreground"><ShieldCheck className="h-3.5 w-3.5 text-primary"/>{t('Security workspace')}</div><div><h1 className="text-3xl font-semibold tracking-tight">{t('Projects')}</h1><p className="mt-1 max-w-2xl text-sm text-muted-foreground">{t('Your security validation workspaces, assets, risk posture and latest assurance activity in one place.')}</p></div></div><div className="flex flex-wrap gap-2"><Link to="/validations/new" className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground"><Sparkles className="h-4 w-4"/>{t('New validation')}</Link><button type="button" onClick={()=>setCreateOpen(true)} className="inline-flex items-center gap-2 rounded-lg border bg-card px-4 py-2.5 text-sm font-medium hover:bg-accent"><Plus className="h-4 w-4"/>{t('New project')}</button></div></header>

    <section className="grid gap-3 sm:grid-cols-3">{[[t('Active workspaces'),projects.length,t('Projects')],[t('Tracked assets'),totalAssets,t('Assets')],[t('Average security score'),averageScore==null?'—':averageScore,highRisk?`${highRisk} ${t('high-risk workspaces')}`:t('No high-risk workspaces')]].map(([label,value,hint])=><div key={String(label)} className="enterprise-card rounded-xl p-4"><p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p><div className="mt-2 flex items-end justify-between gap-3"><span className={cn('text-2xl font-semibold tracking-tight',label===t('Average security score')&&scoreClass(averageScore))}>{String(value)}</span><span className="text-right text-xs text-muted-foreground">{String(hint)}</span></div></div>)}</section>

    <section className="enterprise-card rounded-xl"><div className="flex flex-col gap-3 border-b p-4 sm:flex-row sm:items-center sm:justify-between"><div><h2 className="font-semibold">{t('Project registry')}</h2><p className="text-xs text-muted-foreground">{t('Live data from the AegisScan API')}</p></div><div className="relative w-full sm:max-w-sm"><Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"/><input value={q} onChange={e=>setQ(e.target.value)} placeholder={t('Search projects…')} className="h-9 w-full rounded-lg border bg-background ps-9 pe-3 text-sm outline-none focus:ring-2 focus:ring-primary/30"/></div></div>
      {isLoading?<div className="space-y-3 p-4"><Skeleton className="h-12 w-full"/><Skeleton className="h-12 w-full"/><Skeleton className="h-12 w-full"/></div>:isError?<div className="flex flex-col items-center gap-3 p-12 text-center"><AlertCircle className="h-7 w-7 text-destructive"/><p className="font-medium">{t('Projects could not be loaded')}</p><button type="button" onClick={()=>refetch()} className="rounded-lg border px-3 py-2 text-sm">{t('Retry')}</button></div>:items.length===0?<div className="flex flex-col items-center gap-3 p-14 text-center"><FolderKanban className="h-7 w-7 text-muted-foreground"/><p className="font-medium">{q?t('No matching projects'):t('No projects yet')}</p><p className="text-sm text-muted-foreground">{q?t('Try a different name, owner or risk filter.'):t('Create a project to start organizing assets and validations.')}</p>{!q&&<button type="button" onClick={()=>setCreateOpen(true)} className="rounded-lg bg-primary px-3 py-2 text-sm font-medium text-primary-foreground">{t('Create project')}</button>}</div>:<div className="overflow-x-auto"><table className="w-full min-w-[1020px] text-sm"><thead><tr className="border-b bg-muted/20 text-left text-xs text-muted-foreground">{[t('Project'),t('Owner'),t('Assets'),t('Last validation'),t('Score'),t('Risk'),t('Status'),t('Updated'),''].map(h=><th key={h} className="px-4 py-3 font-medium">{h}</th>)}</tr></thead><tbody>{items.map(p=><tr key={p.id} className="group border-b last:border-0 hover:bg-muted/20"><td className="px-4 py-4"><Link to={`/projects/${p.id}`} className="inline-flex items-center gap-2 font-medium hover:text-primary"><span className="rounded-md border bg-background p-1.5"><FolderKanban className="h-4 w-4 text-primary"/></span>{p.name}<ArrowUpRight className="h-3.5 w-3.5 opacity-0 transition group-hover:opacity-100"/></Link></td><td className="px-4 py-4 text-muted-foreground">{p.owner||t('Not reported')}</td><td className="px-4 py-4 font-medium">{p.assets??'—'}</td><td className="px-4 py-4"><div className="font-mono text-xs">{p.last_validation?<Link to={`/scan/${p.last_validation.id}/results`} className="hover:text-primary">{p.last_validation.id}</Link>:t('Not reported')}</div><div className="mt-1 text-[11px] text-muted-foreground">{p.last_validation?.status||''}</div></td><td className={cn('px-4 py-4 font-semibold',scoreClass(p.security_score))}>{p.security_score==null?'—':p.security_score}</td><td className="px-4 py-4"><span className={cn('rounded-full border px-2 py-1 text-xs font-medium capitalize',riskClass(p.risk))}>{p.risk||t('Not reported')}</span></td><td className="px-4 py-4"><span className="rounded-full border bg-muted/40 px-2 py-1 text-xs capitalize">{p.status||t('Not reported')}</span></td><td className="px-4 py-4 text-xs text-muted-foreground">{p.updated_at?new Date(p.updated_at).toLocaleString():t('Not reported')}</td><td className="px-4 py-4 text-right"><Link to={`/projects/${p.id}`} className="rounded-md p-2 text-muted-foreground hover:bg-accent" aria-label={`${t('Open')} ${p.name}`}><ArrowUpRight className="h-4 w-4"/></Link></td></tr>)}</tbody></table></div>}
    </section>

    {createOpen&&<div className="fixed inset-0 z-50 grid place-items-center bg-black/55 p-4 backdrop-blur-sm" role="dialog" aria-modal="true"><div className="enterprise-card w-full max-w-xl rounded-3xl p-6 shadow-2xl"><div className="flex items-start justify-between gap-4"><div><div className="text-xs font-semibold uppercase tracking-[0.16em] text-primary">{t('Workspace')}</div><h2 className="mt-2 text-2xl font-semibold">{t('New project')}</h2></div><button type="button" onClick={()=>!creating&&setCreateOpen(false)} className="rounded-xl border p-2" aria-label={t('Close')}><X className="h-4 w-4"/></button></div><div className="mt-6 space-y-4"><label className="block"><span className="text-sm font-medium">{t('Project name')}</span><input autoFocus value={name} onChange={e=>setName(e.target.value)} className="mt-2 h-11 w-full rounded-xl border bg-background px-3 text-sm"/></label><label className="block"><span className="text-sm font-medium">{t('Description')}</span><textarea value={description} onChange={e=>setDescription(e.target.value)} rows={4} className="mt-2 w-full rounded-xl border bg-background p-3 text-sm"/></label><label className="block"><span className="text-sm font-medium">{t('Environment')}</span><select value={environment} onChange={e=>setEnvironment(e.target.value)} className="mt-2 h-11 w-full rounded-xl border bg-background px-3 text-sm"><option value="development">{t('Development')}</option><option value="staging">{t('Staging')}</option><option value="production">{t('Production')}</option></select></label></div><div className="mt-7 flex justify-end gap-2"><button type="button" onClick={()=>setCreateOpen(false)} disabled={creating} className="rounded-xl border px-4 py-2.5 text-sm">{t('Cancel')}</button><button type="button" onClick={createProject} disabled={creating||!name.trim()} className="rounded-xl bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-50">{creating?t('Creating project…'):t('Create project')}</button></div></div></div>}
  </div>
}
