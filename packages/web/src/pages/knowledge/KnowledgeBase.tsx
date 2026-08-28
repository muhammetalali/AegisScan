import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ArrowUpRight, BookOpen, ExternalLink, FileText, Filter, Lightbulb, Loader2, RefreshCw, Shield, ShieldCheck } from 'lucide-react'
import { Link } from 'react-router-dom'
import { apiHelpers } from '@/services/api'

type Article = {
  id: string
  title: string
  slug: string
  type: 'best_practice' | 'remediation_guide' | 'security_policy' | 'lesson_learned' | 'faq' | string
  difficulty?: string
  category_name?: string
  tags?: string[]
  summary?: string
  content?: string
  version?: string
  published_at?: string | null
  view_count?: number
  related_vulnerability_ids?: string[]
  related_control_ids?: string[]
  related_vulnerability_count?: number
  related_control_count?: number
}

type Response = Article[] | { results?: Article[]; items?: Article[] }
const unwrap = (data?: Response): Article[] => Array.isArray(data) ? data : data?.results ?? data?.items ?? []
const TYPES = [
  ['all', 'All knowledge'],
  ['best_practice', 'Best practices'],
  ['remediation_guide', 'Remediation guides'],
  ['security_policy', 'Policies'],
  ['lesson_learned', 'Lessons learned'],
  ['faq', 'FAQs'],
] as const

export const KnowledgeBase = () => {
  const [type, setType] = useState<string>('all')
  const [search, setSearch] = useState('')
  const query = useQuery<Response>({ queryKey: ['knowledge-articles', type, search], queryFn: () => apiHelpers.get<Response>(`/knowledge/articles/?${new URLSearchParams({ ...(type !== 'all' ? { type } : {}), ...(search.trim() ? { search: search.trim() } : {}) }).toString()}`), staleTime: 30_000 })
  const articles = useMemo(() => unwrap(query.data), [query.data])
  const visible = articles.filter((article) => type === 'all' || article.type === type)

  return <div className="space-y-6">
    <header><div className="mb-2 inline-flex items-center gap-2 rounded-full border bg-card px-3 py-1 text-xs text-muted-foreground"><BookOpen className="h-3.5 w-3.5 text-primary" /> Source-backed security knowledge</div><h1 className="text-3xl font-semibold tracking-tight">Knowledge Center</h1><p className="mt-1 max-w-3xl text-sm text-muted-foreground">Published guidance is loaded from the Knowledge API and can be connected to real vulnerability findings and compliance controls. No static demo cards are rendered.</p></header>
    <section className="rounded-xl border bg-card p-3 shadow-sm"><div className="flex flex-wrap gap-2">{TYPES.map(([value, label]) => <button key={value} type="button" onClick={() => setType(value)} className={`rounded-lg px-3 py-2 text-sm ${type === value ? 'bg-primary text-primary-foreground' : 'hover:bg-accent'}`}>{label}</button>)}<div className="ml-auto flex w-full min-w-56 max-w-sm items-center gap-2 rounded-lg border px-3"><Filter className="h-4 w-4 text-muted-foreground" /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search published guidance..." className="h-9 w-full bg-transparent text-sm outline-none" /></div></div></section>

    {query.isLoading ? <div className="flex min-h-60 items-center justify-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Loading live knowledge...</div> : query.isError ? <div className="rounded-xl border border-destructive/20 bg-destructive/5 p-8 text-center"><p className="font-medium">Knowledge data could not be loaded</p><p className="mt-1 text-sm text-muted-foreground">The platform did not return a usable published-article response.</p><button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border bg-card px-3 py-2 text-sm font-medium"><RefreshCw className="h-4 w-4" /> Retry</button></div> : visible.length === 0 ? <div className="rounded-xl border bg-card p-10 text-center"><BookOpen className="mx-auto h-8 w-8 text-muted-foreground" /><p className="mt-3 font-medium">No published guidance matches this view</p><p className="mt-1 text-sm text-muted-foreground">This state is intentionally empty: no synthetic security knowledge is inserted into the workspace.</p></div> : <div className="grid gap-4 lg:grid-cols-2">{visible.map((article) => <article key={article.id} className="rounded-xl border bg-card p-5 shadow-sm"><div className="flex items-start gap-3"><div className="rounded-lg border bg-muted/30 p-2">{article.type === 'lesson_learned' ? <Lightbulb className="h-5 w-5 text-primary" /> : article.type === 'security_policy' ? <ShieldCheck className="h-5 w-5 text-primary" /> : article.type === 'faq' ? <FileText className="h-5 w-5 text-primary" /> : <Shield className="h-5 w-5 text-primary" />}</div><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><h2 className="font-semibold">{article.title}</h2><span className="rounded-full bg-muted px-2 py-0.5 text-[10px] capitalize">{String(article.type).replaceAll('_', ' ')}</span></div><p className="mt-1 text-xs text-muted-foreground">{article.category_name || 'Security knowledge'} {article.difficulty ? `· ${article.difficulty}` : ''} {article.version ? `· v${article.version}` : ''}</p></div></div><p className="mt-4 text-sm leading-6 text-muted-foreground">{article.summary || 'No summary supplied by the published source.'}</p><div className="mt-4 grid gap-2 sm:grid-cols-3"><div className="rounded-lg border p-3"><div className="text-[10px] uppercase tracking-wide text-muted-foreground">Findings</div><div className="mt-1 font-semibold">{article.related_vulnerability_count ?? article.related_vulnerability_ids?.length ?? 0}</div></div><div className="rounded-lg border p-3"><div className="text-[10px] uppercase tracking-wide text-muted-foreground">Controls</div><div className="mt-1 font-semibold">{article.related_control_count ?? article.related_control_ids?.length ?? 0}</div></div><div className="rounded-lg border p-3"><div className="text-[10px] uppercase tracking-wide text-muted-foreground">Views</div><div className="mt-1 font-semibold">{article.view_count ?? 0}</div></div></div><div className="mt-4 flex flex-wrap items-center gap-2 text-xs"><Link to={`/knowledge/${article.slug}`} className="inline-flex items-center gap-1 rounded-lg bg-primary px-3 py-2 font-medium text-primary-foreground">Read guidance <ArrowUpRight className="h-3.5 w-3.5" /></Link>{(article.related_vulnerability_ids?.length ?? 0) > 0 && <Link to={`/vulnerabilities?ids=${article.related_vulnerability_ids?.join(',')}`} className="inline-flex items-center gap-1 rounded-lg border px-3 py-2 hover:bg-accent">Related findings <ExternalLink className="h-3.5 w-3.5" /></Link>}{(article.related_control_ids?.length ?? 0) > 0 && <Link to={`/compliance?controls=${article.related_control_ids?.join(',')}`} className="inline-flex items-center gap-1 rounded-lg border px-3 py-2 hover:bg-accent">Related controls <ExternalLink className="h-3.5 w-3.5" /></Link>}</div></article>)}</div>}
  </div>
}
