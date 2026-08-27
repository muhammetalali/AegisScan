export type AssuranceSourceKind = 'scanner' | 'asset_inventory' | 'evidence' | 'validation' | 'compliance' | 'threat_intel' | 'ticketing'

export type AssuranceSource = { id: string; name: string; kind: AssuranceSourceKind; trust: number; freshness: number; status: 'connected' | 'degraded' | 'unavailable'; records: number; updatedAt?: string }

export type AssuranceSignal = { sourceId: string; entityId: string; signal: 'risk' | 'finding' | 'evidence' | 'control' | 'asset' | 'validation' | 'threat'; value: number; confidence: number; observedAt?: string }

export type AssuranceCorrelation = { entityId: string; sourceCount: number; agreement: number; confidence: number; signals: AssuranceSignal[] }

export function correlateSignals(entityId: string, signals: AssuranceSignal[], sources: AssuranceSource[]): AssuranceCorrelation {
  const related = signals.filter((signal) => signal.entityId === entityId)
  const usable = related.filter((signal) => sources.some((source) => source.id === signal.sourceId && source.status === 'connected'))
  const sourceCount = new Set(usable.map((signal) => signal.sourceId)).size
  const trustWeighted = usable.reduce((sum, signal) => { const source = sources.find((item) => item.id === signal.sourceId); return sum + signal.confidence * ((source?.trust ?? 0) / 100) }, 0)
  const trustBase = usable.reduce((sum, signal) => sum + ((sources.find((item) => item.id === signal.sourceId)?.trust ?? 0) / 100), 0)
  const confidence = trustBase ? Math.round((trustWeighted / trustBase) * 100) : 0
  const agreement = usable.length > 1 ? Math.round((usable.reduce((sum, signal, _, all) => sum + Math.abs(signal.value - (all.reduce((a, item) => a + item.value, 0) / all.length)), 0) / usable.length)) : 0
  return { entityId, sourceCount, agreement: Math.max(0, 100 - agreement), confidence, signals: usable }
}
