import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AlertCircle, ArrowUpRight, FolderKanban, Plus, Search, ShieldCheck, Sparkles } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'
import { Skeleton } from '@/components/ui/skeleton'

type Project = {
  id: string
  name: string
  owner?: string
  assets?: number
  lastValidation?: string | null
  score?: number | null
  risk?: string | null
  status?: string | null
  updated?: string | null
}

type ProjectsResponse = Project[] | { items?: Project[]; results?: Project[]; count?: number }

const unwrapProjects = (data: ProjectsResponse | undefined): Project[] => {
  if (Array.isArray(data)) return data
  return data?.items ?? data?.results ?? []
}

const riskClass = (risk?: string | null) => {
  switch (risk?.toLowerCase()) {
    case 'critical': return 'border-destructive/30 bg-destructive/10 text-destructive'
    case 'high': return 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400'
    case 'medium': return 'border-yellow-500/30 bg-yellow-500/10 text-yellow-700 dark:text-yellow-400'
    default: return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
  }
}

const scoreClass = (score?: number | null) => {
  if (score == null) return 'text-muted-foreground'
  if (score >= 80) return 'text-emerald-600 dark:text-emerald-400'
  if (score >= 60) return 'text-amber-600 dark:text-amber-400'
  return 'text-destructive'
}

export const Projects = () => {
  const [q, setQ] = useState('')
  const { data, isLoading, isError, refetch } = useQuery<ProjectsResponse>({
    queryKey: ['projects'],
    queryFn: () => apiHelpers.get<ProjectsResponse>('/projects'),
    staleTime: 30_000,
  })

  const projects = unwrapProjects(data)
  const items = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (!needle) return projects
    return projects.filter((project) =>
      [project.name, project.owner, project.risk, project.status].some((value) => value?.toLowerCase().includes(needle)),
    )
  }, [projects, q])

  const totalAssets = projects.reduce((sum, project) => sum + (project.assets ?? 0), 0)
  const scoredProjects = projects.filter((project) => project.score != null)
  const averageScore = scoredProjects.length
    ? Math.round(scoredProjects.reduce((sum, project) => sum + Number(project.score), 0) / scoredProjects.length)
    : null
  const highRisk = projects.filter((project) => ['critical', 'high'].includes(project.risk?.toLowerCase() ?? '')).length

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="space-y-2">
          <div className="inline-flex items-center gap-2 rounded-full border bg-card/80 px-3 py-1 text-xs text-muted-foreground">
            <ShieldCheck className="h-3.5 w-3.5 text-primary" /> Security workspace
          </div>
          <div>
            <h1 className="text-3xl font-semibold tracking-tight">Projects</h1>
            <p className="mt-1 max-w-2xl text-sm text-muted-foreground">Your security validation workspaces, assets, risk posture and latest assurance activity in one place.</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Link to="/validations/new" className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground shadow-sm transition hover:opacity-90">
            <Sparkles className="h-4 w-4" /> New validation
          </Link>
          <button type="button" className="inline-flex items-center gap-2 rounded-lg border bg-card px-4 py-2.5 text-sm font-medium transition hover:bg-accent">
            <Plus className="h-4 w-4" /> New project
          </button>
        </div>
      </header>

      <section className="grid gap-3 sm:grid-cols-3">
        {[
          ['Projects', projects.length.toString(), 'Active security workspaces'],
          ['Assets', totalAssets.toString(), 'Tracked attack surface'],
          ['Average score', averageScore == null ? '—' : `${averageScore}`, highRisk ? `${highRisk} high-risk workspace${highRisk > 1 ? 's' : ''}` : 'No high-risk workspaces'],
        ].map(([label, value, hint]) => (
          <div key={label} className="rounded-xl border bg-card p-4 shadow-sm">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
            <div className="mt-2 flex items-end justify-between gap-3">
              <span className={cn('text-2xl font-semibold tracking-tight', label === 'Average score' && scoreClass(averageScore))}>{value}</span>
              <span className="text-right text-xs text-muted-foreground">{hint}</span>
            </div>
          </div>
        ))}
      </section>

      <section className="rounded-xl border bg-card shadow-sm">
        <div className="flex flex-col gap-3 border-b p-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="font-semibold">Project registry</h2>
            <p className="text-xs text-muted-foreground">Live data from the AegisScan API</p>
          </div>
          <div className="relative w-full sm:max-w-sm">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <input value={q} onChange={(event) => setQ(event.target.value)} placeholder="Search projects..." className="h-9 w-full rounded-lg border bg-background pl-9 pr-3 text-sm outline-none ring-offset-background transition focus:ring-2 focus:ring-primary/30" aria-label="Search projects" />
          </div>
        </div>

        {isLoading ? (
          <div className="space-y-3 p-4"><Skeleton className="h-12 w-full" /><Skeleton className="h-12 w-full" /><Skeleton className="h-12 w-full" /></div>
        ) : isError ? (
          <div className="flex flex-col items-center justify-center gap-3 p-12 text-center">
            <div className="rounded-full border border-destructive/20 bg-destructive/10 p-3"><AlertCircle className="h-5 w-5 text-destructive" /></div>
            <div><p className="font-medium">Projects could not be loaded</p><p className="mt-1 text-sm text-muted-foreground">The API did not return a usable response. Your workspace was not replaced with demo data.</p></div>
            <button type="button" onClick={() => refetch()} className="rounded-lg border bg-card px-3 py-2 text-sm font-medium hover:bg-accent">Retry</button>
          </div>
        ) : items.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-3 p-14 text-center">
            <div className="rounded-full border bg-muted/40 p-3"><FolderKanban className="h-5 w-5 text-muted-foreground" /></div>
            <div><p className="font-medium">{q ? 'No matching projects' : 'No projects yet'}</p><p className="mt-1 text-sm text-muted-foreground">{q ? 'Try a different name, owner or risk filter.' : 'Create a project to start organizing assets and validations.'}</p></div>
            {!q && <button type="button" className="rounded-lg bg-primary px-3 py-2 text-sm font-medium text-primary-foreground">Create project</button>}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[920px] text-sm">
              <thead><tr className="border-b bg-muted/20 text-left text-xs text-muted-foreground">
                {['Project', 'Owner', 'Assets', 'Last validation', 'Score', 'Risk', 'Status', 'Updated', ''].map((heading) => <th key={heading} className="px-4 py-3 font-medium">{heading}</th>)}
              </tr></thead>
              <tbody>
                {items.map((project) => (
                  <tr key={project.id} className="group border-b last:border-0 transition hover:bg-muted/20">
                    <td className="px-4 py-4"><Link to={`/projects/${project.id}`} className="inline-flex items-center gap-2 font-medium hover:text-primary"><span className="rounded-md border bg-background p-1.5"><FolderKanban className="h-4 w-4 text-primary" /></span>{project.name}<ArrowUpRight className="h-3.5 w-3.5 opacity-0 transition group-hover:opacity-100" /></Link></td>
                    <td className="px-4 py-4 text-muted-foreground">{project.owner || '—'}</td>
                    <td className="px-4 py-4 font-medium">{project.assets ?? '—'}</td>
                    <td className="px-4 py-4 font-mono text-xs text-muted-foreground">{project.lastValidation || 'Not validated'}</td>
                    <td className={cn('px-4 py-4 font-semibold', scoreClass(project.score))}>{project.score == null ? '—' : project.score}</td>
                    <td className="px-4 py-4"><span className={cn('rounded-full border px-2 py-1 text-xs font-medium capitalize', riskClass(project.risk))}>{project.risk || 'unknown'}</span></td>
                    <td className="px-4 py-4"><span className="rounded-full border bg-muted/40 px-2 py-1 text-xs capitalize">{project.status || 'unknown'}</span></td>
                    <td className="px-4 py-4 text-xs text-muted-foreground">{project.updated || '—'}</td>
                    <td className="px-4 py-4 text-right"><Link to={`/projects/${project.id}`} className="rounded-md p-2 text-muted-foreground hover:bg-accent hover:text-foreground" aria-label={`Open ${project.name}`}><ArrowUpRight className="h-4 w-4" /></Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
