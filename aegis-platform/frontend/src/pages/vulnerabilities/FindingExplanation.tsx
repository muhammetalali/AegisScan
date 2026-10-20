import { useLanguageStore } from '@/stores/languageStore'

type Finding = Record<string, unknown>

export function explainFinding(f: Finding) {
  const title = String(f.title || '')
  const isPortObservation = /(?:exposed|open)\s+tcp\s+port/i.test(title) || (
    String(f.source_engine || '').toLowerCase() === 'nmap' && /\bport\b/i.test(title)
  )
  const port = title.match(/\bport\s+(\d{1,5})\b/i)?.[1]
  const asset = String(f.asset_target || f.asset_name || f.asset_id || '')
  const description = typeof f.description === 'string' ? f.description.trim() : ''
  const impact = typeof f.impact === 'string' ? f.impact.trim() : ''
  const remediation = typeof f.remediation === 'string' ? f.remediation.trim() :
    typeof f.solution === 'string' ? f.solution.trim() : ''

  if (isPortObservation) return {
    category: 'service_observation' as const,
    what: 'The scanner detected an accessible TCP service. An open port alone is not proof of a vulnerability.',
    where: [asset, port && `TCP ${port}`].filter(Boolean).join(' · '),
    how: 'A person with network access may contact the exposed service. Exploitation would require a separate, confirmed weakness in that service or its configuration.',
    fix: 'Confirm that this service is necessary, restrict access to trusted networks, apply vendor security updates and verify the configuration.',
    sourceDescription: description,
    sourceImpact: impact,
    sourceRemediation: remediation,
  }
  return {
    category: 'finding' as const,
    what: description || 'A security scanner recorded this finding; consult the linked evidence to confirm the exact behavior.',
    where: asset || 'The precise affected endpoint was not provided by the scanner.',
    how: impact || 'The available record does not establish a verified exploitation method or impact. Review the engine evidence before assessing exploitability.',
    fix: remediation || 'Confirm the root cause from the evidence, apply a targeted correction and revalidate before marking it resolved.',
    sourceDescription: '',
    sourceImpact: '',
    sourceRemediation: '',
  }
}

export function FindingExplanation({ finding }: { finding: Finding }) {
  const t = useLanguageStore((s) => s.t)
  const x = explainFinding(finding)
  return <section className="rounded-2xl border bg-card p-5 md:p-6">
    <h2 className="text-xl font-semibold">{t('Understand this security finding')}</h2>
    <p className="mt-2 text-sm text-muted-foreground">{t('These explanations use saved scanner data. They do not claim exploitation unless independently verified.')}</p>
    {x.category === 'service_observation' && <p className="mt-3 rounded-xl border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-sm">{t('This is an exposed service observation, not a confirmed vulnerability.')}</p>}
    <div className="mt-4 grid gap-3 md:grid-cols-2">
      {[
        [t('What was found?'), t(x.what)],
        [t('Where was it observed?'), x.where],
        [t('How could it affect security?'), t(x.how)],
        [t('What should be done?'), t(x.fix)],
      ].map(([label, value]) => <div key={label} className="rounded-xl border bg-muted/10 p-4">
        <h3 className="text-sm font-semibold">{label}</h3>
        <p className="mt-2 break-words text-sm leading-7 text-muted-foreground" dir="auto">{value}</p>
      </div>)}
    </div>
    {(x.sourceDescription || x.sourceImpact || x.sourceRemediation) && <details className="mt-4 rounded-xl border p-4 text-sm">
      <summary className="cursor-pointer font-semibold">{t('Scanner original explanations')}</summary>
      {x.sourceDescription && <p dir="auto" className="mt-2 break-words">{x.sourceDescription}</p>}
      {x.sourceImpact && <p dir="auto" className="mt-2 break-words">{x.sourceImpact}</p>}
      {x.sourceRemediation && <p dir="auto" className="mt-2 break-words">{x.sourceRemediation}</p>}
    </details>}
  </section>
}
