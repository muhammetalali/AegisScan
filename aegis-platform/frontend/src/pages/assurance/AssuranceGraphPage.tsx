import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { apiHelpers } from '@/services/api'
import { AssuranceGraphView } from '@/components/security/AssuranceGraphView'
import { graphFromCorrelationPayload, graphMetrics } from '@/components/security/AssuranceGraph'
import { AssuranceGraphIntelligencePanel, type GraphIntelligence } from '@/components/security/AssuranceGraphIntelligencePanel'
import { useLanguageStore } from '@/stores/languageStore'

export const AssuranceGraphPage = () => {
  const t = useLanguageStore((state) => state.t)
  const query = useQuery({ queryKey: ['assurance-graph-intelligence'], queryFn: () => apiHelpers.get<any>('/assurance/graph') })
  if (query.isLoading) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">{t('Loading assurance graph intelligence…')}</div>
  if (query.error) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center">
    <div>
      <h1 className="text-lg font-bold">{t('Assurance graph unavailable')}</h1>
      <p className="mt-2 text-sm text-muted-foreground">{t('Live graph intelligence could not be retrieved.')}</p>
      <button type="button" onClick={() => query.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-4 w-4" />{t('Retry')}</button>
    </div>
  </div>

  const graph = graphFromCorrelationPayload(query.data)
  const metrics = graphMetrics(graph)
  const intelligence = query.data?.intelligence as GraphIntelligence | undefined
  const investigate = (id: string | null) => {
    if (!id) return
    const node = graph.nodes.find((item) => item.id === id)
    const validationId = node?.metadata?.validationId
    if (typeof validationId === 'string' && validationId) window.location.assign('/validations/' + encodeURIComponent(validationId) + '/results')
  }

  const metricsCards = [
    { label: 'Nodes', value: metrics.nodes },
    { label: 'Relations', value: metrics.edges },
    { label: 'Conflicts', value: metrics.conflicts },
    { label: 'Evidence-backed', value: metrics.evidenceBacked },
    { label: 'Avg confidence', value: `${metrics.averageConfidence}%` },
    { label: 'Critical', value: metrics.criticalNodes },
  ]

  return <div className="space-y-5">
    <header>
      <div className="text-xs font-semibold text-primary">{t('Assurance intelligence')}</div>
      <h1 className="mt-1 text-2xl font-bold tracking-tight">{t('Unified Assurance Graph')}</h1>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">{t('Understand how security findings, scanner engines and saved evidence are related.')}</p>
    </header>
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {[
        { label: 'Nodes', value: metrics.nodes },
        { label: 'Relations', value: metrics.edges },
        { label: 'Executive priority', value: intelligence ? `${Math.round(intelligence.executivePriority)}/100` : t('Not reported') },
        { label: 'Risk exposure', value: intelligence ? `${Math.round(intelligence.riskExposure)}/100` : t('Not reported') },
      ].map(({ label, value }) => <div key={label} className="rounded-xl border bg-card p-4">
        <div className="text-xs text-muted-foreground">{t(label)}</div>
        <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
      </div>)}
    </div>

    <AssuranceGraphView graph={graph} onInvestigate={(node) => investigate(node.id)} />

    <details className="rounded-2xl border bg-card p-5">
      <summary className="cursor-pointer text-sm font-semibold">{t('Advanced analysis')} · {t('Investigation priorities and additional metrics')}</summary>
      <p className="mt-3 text-sm text-muted-foreground">{t('Open this section for priority paths, detailed risk indicators and technical analysis.')}</p>
      <div className="mt-4 space-y-5">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">{metricsCards.map(({ label, value }) => <div key={label} className="rounded-xl border bg-background/30 p-3">
          <div className="text-xs text-muted-foreground">{t(label)}</div>
          <div className="mt-1 text-xl font-semibold tabular-nums">{value}</div>
        </div>)}</div>
        {intelligence && <AssuranceGraphIntelligencePanel intelligence={intelligence} onInvestigate={investigate} />}
      </div>
    </details>
  </div>
}
