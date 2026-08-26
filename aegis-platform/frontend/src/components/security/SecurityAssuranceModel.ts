export type SecurityAssuranceModel = {
  securityScore: number
  scoreDelta: number
  critical: number
  high: number
  remediationRate: number
  controlCoverage: number
  validationCoverage: number
  riskExposure: number
  openExceptions: number
}

export function normalizeAssuranceModel(summary: any, risk: any): SecurityAssuranceModel {
  return {
    securityScore: Number(summary?.security_score ?? summary?.score ?? 0),
    scoreDelta: Number(summary?.score_delta ?? 0),
    critical: Number(risk?.critical ?? 0),
    high: Number(risk?.high ?? 0),
    remediationRate: Number(summary?.remediation_rate ?? 0),
    controlCoverage: Number(summary?.control_coverage ?? 0),
    validationCoverage: Number(summary?.validation_coverage ?? 0),
    riskExposure: Number(summary?.risk_exposure ?? 0),
    openExceptions: Number(summary?.open_exceptions ?? 0),
  }
}
