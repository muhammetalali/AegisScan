import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, ExternalLink, Loader2 } from 'lucide-react'
import { apiHelpers } from '@/services/api'

type Article = { id: string; title: string; slug: string; type: string; difficulty?: string; category_name?: string; content?: string; summary?: string; published_at?: string | null; related_vulnerability_ids?: string[]; related_control_ids?: string[] }

export const KnowledgeArticle = () => {
  const { slug } = useParams<{ slug: string }>()
  const query = useQuery<Article>({ queryKey: ['knowledge-article', slug], queryFn: () => apiHelpers.get<Article>(`/knowledge/articles/${slug}/`), enabled: Boolean(slug) })
  if (query.isLoading) return <div className="flex min-h-60 items-center justify-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Loading published guidance...</div>
  if (query.isError || !query.data) return <div className="rounded-xl border bg-card p-10 text-center"><p className="font-medium">Published article unavailable</p><p className="mt-1 text-sm text-muted-foreground">The requested knowledge article was not returned by the live Knowledge API.</p><Link to="/knowledge" className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm"><ArrowLeft className="h-4 w-4" /> Back to Knowledge Center</Link></div>
  const article = query.data
  return <article className="mx-auto max-w-4xl space-y-6"><div><Link to="/knowledge" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground"><ArrowLeft className="h-4 w-4" /> Knowledge Center</Link><div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-muted-foreground"><span className="rounded-full bg-muted px-2 py-1 capitalize">{article.type.replaceAll('_', ' ')}</span>{article.category_name && <span>{article.category_name}</span>}{article.difficulty && <span>· {article.difficulty}</span>}</div><h1 className="mt-3 text-3xl font-semibold tracking-tight">{article.title}</h1>{article.summary && <p className="mt-2 text-lg text-muted-foreground">{article.summary}</p>}</div><div className="rounded-xl border bg-card p-6 shadow-sm"><div className="prose prose-sm max-w-none whitespace-pre-wrap leading-7 dark:prose-invert">{article.content}</div></div><div className="flex flex-wrap gap-2"><Link to="/vulnerabilities" className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm">Findings <ExternalLink className="h-3.5 w-3.5" /></Link><Link to="/compliance" className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm">Controls <ExternalLink className="h-3.5 w-3.5" /></Link></div></article>
}
