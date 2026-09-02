export type SecurityAssuranceModel = {
  securityScore: number | null
  scoreDelta: number | null
  critical: number | null
  high: number | null
  remediationRate: number | null
  controlCoverage: number | null
  validationCoverage: number | null
  riskExposure: number | null
  openExceptions: number | null
}

const numberOrNull = (value: unknown): number | null => {
  const parsed = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(parsed) ? parsed : null
}

export function normalizeAssuranceModel(summary: any, risk: any): SecurityAssuranceModel {
  return {
    securityScore: numberOrNull(summary?.security_score ?? summary?.score),
    scoreDelta: numberOrNull(summary?.score_delta),
    critical: numberOrNull(risk?.critical),
    high: numberOrNull(risk?.high),
    remediationRate: numberOrNull(summary?.remediation_rate),
    controlCoverage: numberOrNull(summary?.control_coverage),
    validationCoverage: numberOrNull(summary?.validation_coverage),
    riskExposure: numberOrNull(summary?.risk_exposure),
    openExceptions: numberOrNull(summary?.open_exceptions),
  }
}
