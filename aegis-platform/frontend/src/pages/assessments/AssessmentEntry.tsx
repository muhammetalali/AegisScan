import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { FolderKanban, Loader2, ShieldCheck } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { useLanguageStore } from '@/stores/languageStore'
import { AssessmentLauncher } from './AssessmentLauncher'

type Project = { id: string; name: string; status?: string | null }
type ProjectsPage = Project[] | { results?: Project[]; items?: Project[]; next?: string | null }

/** Read the existing DRF pages instead of relying on the first 20 E2E records. */
export async function loadAssessmentProjects(): Promise<Project[]> {
  const projects: Project[] = []
  for (let page = 1; page <= 20; page += 1) {
    const response = await apiHelpers.get<ProjectsPage>('/projects/', { params: { page } })
    if (Array.isArray(response)) return response.filter((project) => project.status !== 'archived')
    projects.push(...(response.results ?? response.items ?? []))
    if (!response.next) break
  }
  return projects.filter((project) => project.status !== 'archived')
}

/** Hide E2E fixture projects in everyday selectors while preserving explicit legacy selections. */
export function visibleAssessmentProjects(projects: Project[], selectedId = ''): Project[] {
  const regular = projects.filter((project) => !/^External E2E(?:\s|$)/i.test(project.name))
  if (!regular.length) return projects
  return projects.filter((project) => !/^External E2E(?:\s|$)/i.test(project.name) || project.id === selectedId)
}

export function preferAssessmentProject(projects: Project[], requested: string, selected: string): Project | undefined {
  const relevant = projects.filter((p) => !/^External E2E\s/i.test(p.name))
  return projects.find((p) => p.id === requested)
    ?? projects.find((p) => p.id === selected)
    ?? relevant.find((p) => p.name === 'mi-kali')
    ?? relevant[0]
    ?? projects[0]
}

/**
 * A single assessment entry point: user enters an IP, URL, CIDR or file directly.
 * The project only persists evidence and is chosen automatically when available.
 * It is NOT a pre-existing assessment or a prerequisite user workflow.
 */
export const AssessmentEntry = ({ preferredMode = 'network' }: { preferredMode?: 'network' | 'ip' | 'url' | 'file' }) => {
  const t = useLanguageStore((s) => s.t)
  const [selection, setSelection] = useState('')
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState('')
  const projectsQuery = useQuery({ queryKey: ['assessment-entry-projects-all'], queryFn: loadAssessmentProjects, staleTime: 30_000 })
  const [params] = useState(() => new URLSearchParams(window.location.search))
  const requestedId = params.get('project_id') || ''
  const projects = useMemo(() => projectsQuery.data || [], [projectsQuery.data])
  const project = preferAssessmentProject(projects, requestedId, selection)

  const createFirstWorkspace = async () => {
    if (creating) return
    setCreating(true)
    setError('')
    try {
      // Fail closed on ambiguous network retries: re-read before creating.
      const existing = preferAssessmentProject(await loadAssessmentProjects(), '', '')
      if (existing) { setSelection(existing.id); await projectsQuery.refetch(); return }
      const created = await apiHelpers.post<{ id: string }>('/projects/', {
        name: 'مساحة الفحوص', description: 'مساحة تلقائية لحفظ الفحوص والأدلة',
        environment: 'development', status: 'active', tags: [], settings: {}, default_scan_config: {},
      })
      setSelection(created.id)
      await projectsQuery.refetch()
    } catch (err) {
      setError(err instanceof Error ? err.message : t('Unable to create an assessment workspace.'))
    } finally {
      setCreating(false)
    }
  }

  if (projectsQuery.isLoading) return <p className="p-8 text-sm">{t('Loading...')}</p>
  if (projectsQuery.isError) return <div className="enterprise-card p-6">
    <p className="text-sm">{t('Projects could not be loaded')}</p>
    <button type="button" className="mt-3 rounded-xl border px-4 py-2" onClick={() => projectsQuery.refetch()}>{t('Retry')}</button>
  </div>

  return <div className="mx-auto w-full max-w-6xl space-y-4 pb-12">
    {project ? <>
      <section className="enterprise-card flex flex-wrap items-center justify-between gap-3 rounded-2xl p-4">
        <div className="flex items-center gap-2 text-sm">
          <ShieldCheck className="h-4 w-4 text-primary" />
          <span className="font-semibold">{t('Project for saving scan results')}</span>
        </div>
        <select aria-label={t('Project for saving scan results')} value={project.id} onChange={(e) => setSelection(e.target.value)} className="max-w-full rounded-xl border bg-background px-3 py-2 text-sm">
          {visibleAssessmentProjects(projects, project.id).map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}
        </select>
      </section>
      <AssessmentLauncher projectOverride={project.id} preferredMode={preferredMode} />
    </> : <section className="enterprise-card rounded-2xl p-6">
      <div className="flex items-center gap-2 text-lg font-semibold"><FolderKanban className="h-5 w-5 text-primary" />{t('Start a new assessment')}</div>
      <p className="mt-2 text-sm text-muted-foreground">{t('AegisScan will create one workspace automatically to save your first scan and evidence. No earlier scan is needed.')}</p>
      {error && <p role="alert" className="mt-3 text-sm text-destructive">{error}</p>}
      <button type="button" onClick={createFirstWorkspace} disabled={creating} className="mt-4 inline-flex items-center gap-2 rounded-xl bg-primary px-5 py-3 text-sm font-semibold text-primary-foreground disabled:opacity-50">
        {creating && <Loader2 className="h-4 w-4 animate-spin" />}
        {t('Prepare my first assessment')}
      </button>
    </section>}
  </div>
}
