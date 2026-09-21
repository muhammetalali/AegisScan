import { z, type ZodTypeAny } from 'zod'

import { apiHelpers } from '@/services/api'
import {
  AgomActionContractSchema,
  AgomActionExecutionSchema,
  AgomActionRequestCreateInputSchema,
  AgomActionRequestSchema,
  AgomActorAuthoritySchema,
  AgomAuthoritativeCapabilityManifestSchema,
  AgomContractRegistrySchema,
  AgomExecuteActionInputSchema,
  AgomResponsibilityAssignmentSchema,
  AgomResponsibilityChainSchema,
  AgomResponsibilityGrantInputSchema,
  AgomResponsibilityRevokeInputSchema,
  AgomResponsibilityRevocationSchema,
  AgomWorkClaimMutationInputSchema,
  AgomWorkMutationSchema,
  AgomWorkQueueQuerySchema,
  AgomWorkQueueSchema,
  type AgomActionContract,
  type AgomActionExecution,
  type AgomActionRequest,
  type AgomActionRequestCreateInput,
  type AgomActorAuthority,
  type AgomAuthoritativeCapabilityManifest,
  type AgomContractRegistry,
  type AgomExecuteActionInput,
  type AgomResponsibilityAssignment,
  type AgomResponsibilityChain,
  type AgomResponsibilityGrantInput,
  type AgomResponsibilityRevokeInput,
  type AgomResponsibilityRevocation,
  type AgomWorkClaimMutationInput,
  type AgomWorkMutation,
  type AgomWorkQueue,
  type AgomWorkQueueQuery,
  type AgomWorkSourceType,
} from '@/contracts/agom'

export class AgomSdkError extends Error {
  readonly code: string
  readonly status: number | null
  readonly missingRequirements: string[]
  readonly details: unknown

  constructor(message: string, options: { code?: string; status?: number | null; missingRequirements?: string[]; details?: unknown } = {}) {
    super(message)
    this.name = 'AgomSdkError'
    this.code = options.code || 'AGOM_REQUEST_FAILED'
    this.status = options.status ?? null
    this.missingRequirements = options.missingRequirements || []
    this.details = options.details
  }
}

const parse = <T extends ZodTypeAny>(schema: T, value: unknown, surface: string): z.infer<T> => {
  const result = schema.safeParse(value)
  if (!result.success) {
    throw new AgomSdkError('AGOM response contract mismatch on ' + surface + '.', {
      code: 'AGOM_CONTRACT_MISMATCH',
      details: result.error.flatten(),
    })
  }
  return result.data
}

const parseInput = <T extends ZodTypeAny>(schema: T, value: unknown, surface: string): z.infer<T> => {
  const result = schema.safeParse(value)
  if (!result.success) {
    throw new AgomSdkError('Invalid AGOM request contract for ' + surface + '.', {
      code: 'AGOM_CLIENT_VALIDATION',
      details: result.error.flatten(),
    })
  }
  return result.data
}

export const normalizeAgomError = (error: unknown): AgomSdkError => {
  if (error instanceof AgomSdkError) return error
  const candidate = error as { response?: { status?: number; data?: { detail?: unknown } }; message?: string }
  const status = typeof candidate?.response?.status === 'number' ? candidate.response.status : null
  const detail = candidate?.response?.data?.detail
  if (typeof detail === 'string') {
    return new AgomSdkError(detail, { status, details: detail })
  }
  if (Array.isArray(detail)) {
    const messages = detail.map((item) => {
      if (item && typeof item === 'object' && 'msg' in item && typeof (item as { msg?: unknown }).msg === 'string') return (item as { msg: string }).msg
      return String(item)
    })
    return new AgomSdkError(messages.join('; ') || 'AGOM request validation failed.', {
      code: 'AGOM_VALIDATION_ERROR',
      status,
      details: detail,
    })
  }
  if (detail && typeof detail === 'object') {
    const record = detail as Record<string, unknown>
    const reason = typeof record.reason === 'string' ? record.reason : typeof record.message === 'string' ? record.message : 'Governed action was rejected.'
    const code = typeof record.code === 'string' ? record.code : 'AGOM_REQUEST_FAILED'
    const missingRequirements = Array.isArray(record.missing_requirements)
      ? record.missing_requirements.filter((item): item is string => typeof item === 'string')
      : []
    return new AgomSdkError(reason, { code, status, missingRequirements, details: detail })
  }
  return new AgomSdkError(candidate?.message || 'AGOM request failed.', { status, details: error })
}

export const getAgomErrorMessage = (error: unknown, fallback = 'Governed operation failed.') => {
  const normalized = normalizeAgomError(error)
  return normalized.message || fallback
}

export const buildAgomIdempotencyKey = (namespace: string, ...parts: Array<string | number>) => {
  const segments = [namespace, ...parts.map(String)]
    .map((value) => value.trim().replace(/[^A-Za-z0-9._:-]+/g, '_').replace(/^[_:.-]+|[_:.-]+$/g, ''))
    .filter(Boolean)
  const key = segments.join(':')
  if (key.length < 8 || key.length > 128) {
    throw new AgomSdkError('Generated AGOM idempotency key must be between 8 and 128 characters.', {
      code: 'AGOM_CLIENT_VALIDATION',
      details: { namespace, parts },
    })
  }
  return key
}

export const agomPaths = {
  contracts: '/assurance/governance/contracts',
  contract: (actionId: string) => '/assurance/governance/contracts/' + encodeURIComponent(actionId),
  capabilities: (entityType: string, entityId: string) => '/assurance/governance/capabilities/' + encodeURIComponent(entityType) + '/' + encodeURIComponent(entityId),
  execute: '/assurance/governance/actions/execute',
  requests: '/assurance/governance/actions/requests',
  workQueue: '/work-queue',
  workMutation: (sourceType: AgomWorkSourceType, sourceId: string, operation: 'claim' | 'renew' | 'release') =>
    '/work-queue/' + encodeURIComponent(sourceType) + '/' + encodeURIComponent(sourceId) + '/' + operation,
  responsibilityGrant: '/assurance/governance/responsibilities/grants',
  responsibilityRevoke: (assignmentId: string) => '/assurance/governance/responsibilities/' + encodeURIComponent(assignmentId) + '/revoke',
  responsibilityAuthority: '/assurance/governance/responsibilities/authority',
  responsibilityChain: '/assurance/governance/responsibilities/chain',
} as const

const guarded = async <T>(operation: () => Promise<T>) => {
  try {
    return await operation()
  } catch (error) {
    throw normalizeAgomError(error)
  }
}

const buildQuery = (values: Record<string, unknown>) => {
  const params = new URLSearchParams()
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') params.set(key, String(value))
  })
  const query = params.toString()
  return query ? '?' + query : ''
}

const mutateWork = async (
  operation: 'claim' | 'renew' | 'release',
  sourceType: AgomWorkSourceType,
  sourceId: string,
  input: AgomWorkClaimMutationInput,
): Promise<AgomWorkMutation> => guarded(async () => {
  const body = parseInput(AgomWorkClaimMutationInputSchema, input, 'work-queue.' + operation)
  if ((operation === 'claim' || operation === 'renew') && body.lease_seconds === undefined) {
    throw new AgomSdkError('lease_seconds is required for work queue claim and renew.', { code: 'AGOM_CLIENT_VALIDATION' })
  }
  if (operation === 'release' && body.lease_seconds !== undefined) {
    throw new AgomSdkError('lease_seconds must be omitted for work queue release.', { code: 'AGOM_CLIENT_VALIDATION' })
  }
  const response = await apiHelpers.post<unknown>(agomPaths.workMutation(sourceType, sourceId, operation), body)
  return parse(AgomWorkMutationSchema, response, 'work-queue.' + operation)
})

export const agomSdk = {
  async listContracts(): Promise<AgomContractRegistry> {
    return guarded(async () => parse(AgomContractRegistrySchema, await apiHelpers.get<unknown>(agomPaths.contracts), 'contracts'))
  },

  async getContract(actionId: string): Promise<AgomActionContract> {
    const id = String(actionId || '').trim()
    if (!id) throw new AgomSdkError('actionId is required.', { code: 'AGOM_CLIENT_VALIDATION' })
    return guarded(async () => parse(AgomActionContractSchema, await apiHelpers.get<unknown>(agomPaths.contract(id)), 'contract'))
  },

  async getCapabilities(input: { projectId: string; entityType: string; entityId: string }): Promise<AgomAuthoritativeCapabilityManifest> {
    const projectId = String(input.projectId || '').trim()
    const entityType = String(input.entityType || '').trim()
    const entityId = String(input.entityId || '').trim()
    if (!projectId || !entityType || !entityId) {
      throw new AgomSdkError('projectId, entityType and entityId are required.', { code: 'AGOM_CLIENT_VALIDATION' })
    }
    const path = agomPaths.capabilities(entityType, entityId) + buildQuery({ project_id: projectId })
    return guarded(async () => parse(AgomAuthoritativeCapabilityManifestSchema, await apiHelpers.get<unknown>(path), 'capabilities'))
  },

  async createActionRequest(input: AgomActionRequestCreateInput): Promise<AgomActionRequest> {
    return guarded(async () => {
      const body = parseInput(AgomActionRequestCreateInputSchema, input, 'action-request')
      return parse(AgomActionRequestSchema, await apiHelpers.post<unknown>(agomPaths.requests, body), 'action-request')
    })
  },

  async executeAction(input: AgomExecuteActionInput): Promise<AgomActionExecution> {
    return guarded(async () => {
      const body = parseInput(AgomExecuteActionInputSchema, input, 'action-execute')
      return parse(AgomActionExecutionSchema, await apiHelpers.post<unknown>(agomPaths.execute, body), 'action-execute')
    })
  },

  async listWorkQueue(query: AgomWorkQueueQuery = {}): Promise<AgomWorkQueue> {
    return guarded(async () => {
      const parsedQuery = parseInput(AgomWorkQueueQuerySchema, query, 'work-queue.list')
      const response = await apiHelpers.get<unknown>(agomPaths.workQueue + buildQuery(parsedQuery))
      return parse(AgomWorkQueueSchema, response, 'work-queue.list')
    })
  },

  claimWork(sourceType: AgomWorkSourceType, sourceId: string, input: AgomWorkClaimMutationInput) {
    return mutateWork('claim', sourceType, sourceId, input)
  },

  renewWork(sourceType: AgomWorkSourceType, sourceId: string, input: AgomWorkClaimMutationInput) {
    return mutateWork('renew', sourceType, sourceId, input)
  },

  releaseWork(sourceType: AgomWorkSourceType, sourceId: string, input: AgomWorkClaimMutationInput) {
    return mutateWork('release', sourceType, sourceId, input)
  },

  async grantResponsibility(input: AgomResponsibilityGrantInput): Promise<AgomResponsibilityAssignment> {
    return guarded(async () => {
      const body = parseInput(AgomResponsibilityGrantInputSchema, input, 'responsibility.grant')
      const response = await apiHelpers.post<unknown>(agomPaths.responsibilityGrant, body)
      return parse(AgomResponsibilityAssignmentSchema, response, 'responsibility.grant')
    })
  },

  async revokeResponsibility(assignmentId: string, input: AgomResponsibilityRevokeInput): Promise<AgomResponsibilityRevocation> {
    return guarded(async () => {
      const body = parseInput(AgomResponsibilityRevokeInputSchema, input, 'responsibility.revoke')
      const response = await apiHelpers.post<unknown>(agomPaths.responsibilityRevoke(assignmentId), body)
      return parse(AgomResponsibilityRevocationSchema, response, 'responsibility.revoke')
    })
  },

  async getAuthority(input: { organizationId: string; projectId?: string; entityType?: string; entityId?: string }): Promise<AgomActorAuthority> {
    const path = agomPaths.responsibilityAuthority + buildQuery({
      organization_id: input.organizationId,
      project_id: input.projectId,
      entity_type: input.entityType,
      entity_id: input.entityId,
    })
    return guarded(async () => parse(AgomActorAuthoritySchema, await apiHelpers.get<unknown>(path), 'responsibility.authority'))
  },

  async verifyResponsibilityChain(organizationId: string): Promise<AgomResponsibilityChain> {
    const path = agomPaths.responsibilityChain + buildQuery({ organization_id: organizationId })
    return guarded(async () => parse(AgomResponsibilityChainSchema, await apiHelpers.get<unknown>(path), 'responsibility.chain'))
  },
}
