import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, Database, FileText, RefreshCw, Search, ShieldCheck } from 'lucide-react'
import { Link } from 'react-router-dom'

import { apiHelpers } from '@/services/api'
import { WSTGProjectCoverageSchema, type WSTGProjectCoverage } from '@/contracts/api'
import { useLanguageStore } from '@/stores/languageStore'
import { cn } from '@/utils/cn'

type Project = { id: string; name: string }
type ProjectsResponse = Project[] | { items?: Project[]; results?: Project[] }
const unwrapProjects = (data: ProjectsResponse | undefined): Project[] =>
  Array.isArray(data) ? data : data?.items ?? data?.results ?? []

const stateClass = (state: string) => {
  switch (state) {
    case 'observed': return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
    case 'manual_required': return 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400'
    case 'blocked_native_gap': return 'border-destructive/30 bg-destructive/10 text-destructive'
    case 'inconclusive': return 'border-violet-500/30 bg-violet-500/10 text-violet-600 dark:text-violet-400'
    default: return 'border-border bg-muted/30 text-muted-foreground'
  }
}

const labelState = (state: string) => state.split('_').join(' ')

export const WSTGCoveragePage = () => {
  const t = useLanguageStore(s => s.t)
  const [projectId, setProjectId] = useState('')
  const [search, setSearch] = useState('')
  const [state, setState] = useState('')
  const [category, setCategory] = useState('')

  const projectsQuery = useQuery<ProjectsResponse>({
    queryKey: ['wstg-projects'],
    queryFn: () => apiHelpers.get<ProjectsResponse>('/projects/'),
    staleTime: 30_000,
  })
  const projects = unwrapProjects(projectsQuery.data)

  useEffect(() => {
    if (!projectId && projects.length) setProjectId(projects[0].id)
  }, [projectId, projects])

  const coverageQuery = useQuery<WSTGProjectCoverage>({
    queryKey: ['wstg-project-coverage', projectId],
    enabled: Boolean(projectId),
    queryFn: async () => {
      const payload = await apiHelpers.get<unknown>(`/wstg/projects/${projectId}/coverage`)
      return WSTGProjectCoverageSchema.parse(payload)
    },
  })

  const rows = useMemo(() => {
    const data = coverageQuery.data?.tests ?? []
    const needle = search.trim().toLowerCase()
    return data.filter(item => {
      if (state && item.state !== state) return false
      if (category && item.category !== category) return false
      if (!needle) return true
      return [
        item.wstg_id,
        item.title,
        item.classification,
        item.state,
        item.category,
        ...item.capability_ids,
      ].some(value => String(value).toLowerCase().includes(needle))
    })
  }, [coverageQuery.data, search, state, category])

  const categories = useMemo(
    () => Object.keys(coverageQuery.data?.category_summary ?? {}).sort(),
    [coverageQuery.data],
  )

  const summary = coverageQuery.data?.summary

  return <div className="space-y-6 pb-10">
    <section className="enterprise-card rounded-3xl p-6 md:p-8">
      <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.16em] text-primary">
            <ShieldCheck className="h-4 w-4" />OWASP WSTG v4.2
          </div>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight">{t('WSTG observation coverage')}</h1>
          <p className="mt-2 max-w-4xl text-sm leading-7 text-muted-foreground">
            {t('Coverage is derived from trusted persisted evidence and finding lineage. It does not represent a pass, fail, confirmation, closure, or risk disposition decision.')}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Link to="/evidence" className="inline-flex items-center gap-2 rounded-xl border bg-card px-4 py-2.5 text-sm font-semibold hover:bg-accent">
            <Database className="h-4 w-4" />{t('Open evidence')}
          </Link>
          <Link to="/reports" className="inline-flex items-center gap-2 rounded-xl border bg-card px-4 py-2.5 text-sm font-semibold hover:bg-accent">
            <FileText className="h-4 w-4" />{t('Generate report')}
          </Link>
          <button type="button" onClick={() => coverageQuery.refetch()} disabled={!projectId || coverageQuery.isFetching} className="inline-flex items-center gap-2 rounded-xl border bg-card px-4 py-2.5 text-sm font-semibold hover:bg-accent disabled:opacity-50">
            <RefreshCw className={cn('h-4 w-4', coverageQuery.isFetching && 'animate-spin')} />{t('Refresh')}
          </button>
        </div>
      </div>
    </section>

    <section className="enterprise-card rounded-2xl p-4">
      <label className="block max-w-2xl">
        <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{t('Project')}</span>
        <select value={projectId} onChange={e => setProjectId(e.target.value)} className="mt-2 h-11 w-full rounded-xl border bg-background px-3 text-sm">
          <option value="">{projectsQuery.isLoading ? t('Loading...') : t('Select project')}</option>
          {projects.map(project => <option key={project.id} value={project.id}>{project.name}</option>)}
        </select>
      </label>
    </section>

    {summary && <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
      {[
        [t('Observed tests'), `${summary.observed_tests}/${summary.total_tests}`],
        [t('Completion paths'), `${summary.completion_claim_supported_tests}/${summary.total_tests}`],
        [t('Observation coverage'), `${summary.observation_coverage_percent}%`],
        [t('Auto + assisted'), `${summary.auto_assisted_observed}/${summary.auto_assisted_total}`],
        [t('Trusted evidence'), summary.trusted_evidence_records],
        [t('Trusted findings'), summary.trusted_finding_records],
        [t('Rejected lineage'), summary.rejected_lineage_records],
      ].map(([label, value]) => <div key={String(label)} className="enterprise-card rounded-2xl p-4">
        <div className="text-xs text-muted-foreground">{label}</div>
        <div className="mt-2 text-2xl font-semibold">{String(value)}</div>
      </div>)}
    </section>}

    {summary && summary.rejected_lineage_records > 0 && <section className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-4 text-sm">
      <div className="flex items-start gap-3"><AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-600 dark:text-amber-400" /><div>
        <div className="font-semibold">{t('Rejected WSTG lineage detected')}</div>
        <p className="mt-1 text-muted-foreground">{t('One or more persisted lineage records failed canonical fingerprint validation and were excluded from coverage calculations.')}</p>
      </div></div>
    </section>}

    <section className="enterprise-card rounded-2xl p-4">
      <div className="grid gap-3 lg:grid-cols-[1fr_220px_220px]">
        <div className="relative"><Search className="absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><input value={search} onChange={e => setSearch(e.target.value)} placeholder={t('Search WSTG ID, title, capability or classification…')} className="h-11 w-full rounded-xl border bg-background ps-9 pe-3 text-sm outline-none focus:ring-2 focus:ring-primary/20" /></div>
        <select value={state} onChange={e => setState(e.target.value)} className="h-11 rounded-xl border bg-background px-3 text-sm">
          <option value="">{t('All states')}</option>
          {['observed','not_observed','manual_required','inconclusive'].map(value => <option key={value} value={value}>{labelState(value)}</option>)}
        </select>
        <select value={category} onChange={e => setCategory(e.target.value)} className="h-11 rounded-xl border bg-background px-3 text-sm">
          <option value="">{t('All categories')}</option>
          {categories.map(value => <option key={value} value={value}>{value}</option>)}
        </select>
      </div>
    </section>

    {projectsQuery.isError && <section className="enterprise-card rounded-2xl p-10 text-center text-sm text-destructive">{t('Projects could not be loaded')}</section>}
    {!projectsQuery.isError && projectId && coverageQuery.isLoading && <section className="enterprise-card rounded-2xl p-10 text-center text-sm text-muted-foreground">{t('Loading...')}</section>}
    {coverageQuery.isError && <section className="enterprise-card rounded-2xl p-10 text-center"><div className="font-semibold">{t('Unable to load WSTG coverage')}</div><p className="mt-2 text-sm text-muted-foreground">{t('The live coverage contract could not be validated. No synthetic coverage is displayed.')}</p></section>}

    {coverageQuery.data && <section className="enterprise-card overflow-hidden rounded-2xl">
      <div className="border-b px-5 py-4">
        <div className="font-semibold">{coverageQuery.data.project_name}</div>
        <div className="mt-1 text-xs text-muted-foreground">
          {t('Source')}: PostgreSQL · {t('Claim policy')}: observation-only · {rows.length} {t('tests shown')}
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1320px] text-sm">
          <thead><tr className="border-b bg-muted/20 text-xs text-muted-foreground">
            <th className="px-4 py-3 text-start">WSTG</th>
            <th className="px-4 py-3 text-start">{t('Title')}</th>
            <th className="px-4 py-3 text-start">{t('Classification')}</th>
            <th className="px-4 py-3 text-start">{t('State')}</th>
            <th className="px-4 py-3 text-start">{t('Evidence')}</th>
            <th className="px-4 py-3 text-start">{t('Findings')}</th>
            <th className="px-4 py-3 text-start">{t('Capabilities')}</th>
            <th className="px-4 py-3 text-start">{t('Latest observation')}</th>
          </tr></thead>
          <tbody>{rows.length === 0 ? <tr><td colSpan={8} className="px-6 py-16 text-center text-muted-foreground">{t('No WSTG tests match the selected filters')}</td></tr> : rows.map(item => <tr key={item.wstg_id} className="border-b last:border-0 hover:bg-muted/20">
            <td className="px-4 py-3 font-mono text-xs font-semibold">{item.wstg_id}</td>
            <td className="px-4 py-3 max-w-[360px]"><div className="font-medium">{item.title}</div><div className="mt-1 text-[11px] text-muted-foreground">{item.category}</div></td>
            <td className="px-4 py-3 text-xs">{item.classification}</td>
            <td className="px-4 py-3"><span className={cn('rounded-full border px-2 py-1 text-[11px] font-semibold capitalize', stateClass(item.state))}>{labelState(item.state)}</span></td>
            <td className="px-4 py-3 font-semibold">{item.evidence_records}</td>
            <td className="px-4 py-3 font-semibold">{item.finding_records}</td>
            <td className="px-4 py-3"><div className="flex max-w-[280px] flex-wrap gap-1">{item.capability_ids.length ? item.capability_ids.map(value => <span key={value} className="rounded-md border bg-muted/20 px-2 py-1 font-mono text-[10px]">{value}</span>) : <span className="text-xs text-muted-foreground">{t('Not observed')}</span>}</div></td>
            <td className="px-4 py-3 text-xs text-muted-foreground">{item.latest_observed_at ? new Date(item.latest_observed_at).toLocaleString() : t('Not observed')}</td>
          </tr>)}</tbody>
        </table>
      </div>
    </section>}
  </div>
}
