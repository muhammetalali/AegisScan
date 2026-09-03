import { z } from 'zod'

export const ApiErrorSchema = z.object({
  code: z.string(),
  message: z.string(),
  details: z.record(z.unknown()).default({}),
})

export const AttackPathNodeSchema = z.object({ id: z.string(), name: z.string(), kind: z.string(), criticality: z.string(), open_finding_weight: z.number().nonnegative(), internet_exposed: z.boolean() })
export const AttackPathGraphSchema = z.object({
  contract_version: z.literal('1.0'), project_id: z.string(), source: z.literal('postgresql'), generated_at: z.string(),
  nodes: z.array(AttackPathNodeSchema),
  edges: z.array(z.object({ source: z.string(), target: z.string(), relationship: z.string(), metadata: z.record(z.unknown()).default({}) })),
})
export const AttackPathAnalysisSchema = z.object({
  contract_version: z.literal('1.0'), project_id: z.string(), source: z.literal('postgresql'), generated_at: z.string(),
  source_asset_id: z.string(), target_asset_id: z.string(),
  paths: z.array(z.object({ nodes: z.array(z.string()), risk_score: z.number().min(0).max(100), hops: z.number().int().nonnegative() })),
  persisted_attack_path_ids: z.array(z.string()).default([]),
})
export const ComplianceValidationItemSchema = z.object({ id: z.string(), framework: z.string(), control: z.string(), status: z.enum(['pass', 'fail', 'partial', 'not_assessed']), finding_count: z.number().int().nonnegative(), evidence_count: z.number().int().nonnegative() })
export const ComplianceValidationListSchema = z.array(ComplianceValidationItemSchema)
export const UnifiedValidationSchema = z.object({
  contract_version: z.literal('1.0'), id: z.string(), finding_id: z.string().nullable().optional(), target_type: z.enum(['url', 'ip', 'api']), target_value: z.string(),
  profile: z.enum(['quick', 'full', 'custom']), engines: z.array(z.string()), scope: z.string(), status: z.string(), progress: z.number().int().min(0).max(100),
  current_phase: z.string(), created_at: z.string(), audit_note: z.string(),
})
export const TwinScenarioSimulationSchema = z.object({ contract_version: z.literal('1.0'), scenario_id: z.string(), status: z.string(), deterministic: z.boolean(), source: z.literal('postgresql'), pre_change_risk: z.number().nonnegative(), post_change_risk: z.number().nonnegative(), risk_reduction: z.number(), affected_nodes: z.array(z.string()), recommendation: z.string() })

export const apiContractPaths = {
  attackPathGraph: (projectId: string) => `/api/v1/attack-path/projects/${projectId}`,
  attackPathAnalyze: (projectId: string) => `/api/v1/attack-path/projects/${projectId}/analyze`,
  validationCompliance: (validationId: string) => `/api/v1/validations/${validationId}/compliance`,
  cveIntelligence: (cveId: string) => `/api/v1/intelligence/cve/${encodeURIComponent(cveId)}`,
  validationContract: '/api/v1/validation-contract',
} as const
