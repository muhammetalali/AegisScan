import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowRight, FolderKanban, Radar, ShieldCheck } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { useLanguageStore } from '@/stores/languageStore'
import { cn } from '@/utils/cn'

type Project = {
  id: string
  name: string
  environment?: string | null
  status?: string | null
}
type ProjectsResponse = Project[] | { items?: Project[]; results?: Project[] }

const unwrapProjects = (data?: ProjectsResponse): Project[] =>
  Array.isArray(data) ? data : data?.items ?? data?.results ?? []

export const AssessmentEntry = () => {
  const t = useLanguageStore((state) => state.t)
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const requestedProjectId = params.get('project_id') || ''
  const [projectId, setProjectId] = useState(requestedProjectId)
  const projectsQuery = useQuery<ProjectsResponse>({
    queryKey: ['assessment-entry-projects'],
    queryFn: () => apiHelpers.get<ProjectsResponse>('/projects/'),
    staleTime: 30_000,
  })
  const projects = useMemo(
    () => unwrapProjects(projectsQuery.data).filter((project) => project.status !== 'archived'),
    [projectsQuery.data],
  )

  useEffect(() => {
    if (requestedProjectId && projects.some((project) => project.id === requestedProjectId)) {
      setProjectId(requestedProjectId)
    }
  }, [projects, requestedProjectId])

  const selectedProject = projects.find((project) => project.id === projectId)
  const launch = () => {
    if (!selectedProject) return
    navigate(`/projects/${encodeURIComponent(selectedProject.id)}/assess`)
  }

  if (projectsQuery.isLoading) {
    return <div className="grid min-h-[60vh] place-items-center text-sm text-muted-foreground">{t('Loading...')}</div>
  }

  if (projectsQuery.isError) {
    return (
      <div className="mx-auto max-w-3xl">
        <section className="enterprise-card rounded-3xl p-10 text-center">
          <FolderKanban className="mx-auto h-8 w-8 text-destructive" />
          <h1 className="mt-4 text-xl font-semibold">{t('Projects could not be loaded')}</h1>
          <button
            type="button"
            onClick={() => projectsQuery.refetch()}
            className="mt-5 rounded-xl border px-4 py-2 text-sm font-medium"
          >
            {t('Retry')}
          </button>
        </section>
      </div>
    )
  }

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 pb-12">
      <section className="enterprise-card rounded-[2rem] p-6 md:p-8">
        <div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/5 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.18em] text-primary">
          <Radar className="h-3.5 w-3.5" />
          {t('New Assessment')}
        </div>
        <h1 className="mt-4 text-3xl font-semibold tracking-tight md:text-4xl">{t('Choose a project')}</h1>
        <p className="mt-2 max-w-3xl text-sm leading-7 text-muted-foreground">
          {t('Choose the security workspace for this assessment. AegisScan will then open the existing Assessment Launcher for URL, IP, network or file input.')}
        </p>
        <div className="mt-4 inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[10px] font-semibold text-muted-foreground">
          <ShieldCheck className="h-3.5 w-3.5 text-primary" />
          {t('Assets remain an internal evidence anchor and are created or reused automatically.')}
        </div>
      </section>

      {projects.length === 0 ? (
        <section className="enterprise-card rounded-3xl p-10 text-center">
          <FolderKanban className="mx-auto h-8 w-8 text-muted-foreground" />
          <h2 className="mt-4 text-lg font-semibold">{t('No projects yet')}</h2>
          <p className="mt-2 text-sm text-muted-foreground">{t('Create a project to start organizing assets and validations.')}</p>
          <Link to="/projects" className="mt-5 inline-flex rounded-xl bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground">
            {t('Create project')}
          </Link>
        </section>
      ) : (
        <section className="enterprise-card rounded-3xl p-5 md:p-6">
          <div className="grid gap-3 md:grid-cols-2">
            {projects.map((project) => {
              const selected = project.id === projectId
              return (
                <button
                  key={project.id}
                  type="button"
                  onClick={() => setProjectId(project.id)}
                  aria-pressed={selected}
                  className={cn(
                    'rounded-2xl border p-5 text-start transition-all',
                    selected ? 'border-primary bg-primary/5 shadow-lg' : 'hover:-translate-y-0.5 hover:border-primary/30',
                  )}
                >
                  <div className="flex items-center justify-between gap-3">
                    <span className="grid h-9 w-9 place-items-center rounded-xl border bg-background">
                      <FolderKanban className="h-4 w-4 text-primary" />
                    </span>
                    <span className="rounded-full border px-2 py-1 text-[10px] text-muted-foreground">
                      {project.environment || t('Not reported')}
                    </span>
                  </div>
                  <div className="mt-4 font-semibold">{project.name}</div>
                  <div className="mt-1 font-mono text-[10px] text-muted-foreground">{project.id}</div>
                </button>
              )
            })}
          </div>
          <div className="mt-6 flex flex-col gap-3 border-t pt-5 sm:flex-row sm:items-center sm:justify-between">
            <div className="text-xs text-muted-foreground">
              {selectedProject ? selectedProject.name : t('Select project')}
            </div>
            <button
              type="button"
              onClick={launch}
              disabled={!selectedProject}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-primary px-6 py-3 text-sm font-semibold text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50"
            >
              {t('Continue')}
              <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        </section>
      )}
    </div>
  )
}
