import type { AxiosRequestConfig } from 'axios'

import {
  AgomActionContractSchema,
  AgomActionExecutionInputSchema,
  AgomActionExecutionSchema,
  AgomActionRequestInputSchema,
  AgomActionRequestSchema,
  AgomActorAuthoritySchema,
  AgomAuthoritativeCapabilityManifestSchema,
  AgomContractRegistrySchema,
  AgomResponsibilityAssignmentSchema,
  AgomResponsibilityChainSchema,
  AgomResponsibilityGrantInputSchema,
  AgomResponsibilityRevokeInputSchema,
  AgomResponsibilityRevocationSchema,
  AgomWorkLeaseMutationInputSchema,
  AgomWorkMutationSchema,
  AgomWorkQueueSchema,
  AgomWorkReleaseMutationInputSchema,
  AgomWorkSourceTypeSchema,
  type AgomActionExecutionInput,
  type AgomActionRequestInput,
  type AgomResponsibilityGrantInput,
  type AgomResponsibilityRevokeInput,
  type AgomWorkClaimState,
  type AgomWorkLeaseMutationInput,
  type AgomWorkReleaseMutationInput,
  type AgomWorkSourceType,
} from '@/contracts/agom'
import { apiHelpers } from '@/services/api'

const encodeSegment = (value: string) => encodeURIComponent(String(value || '').trim())

const getParsed = async <T>(url: string, schema: { parse: (value: unknown) => T }, config?: AxiosRequestConfig): Promise<T> =>
  schema.parse(await apiHelpers.get<unknown>(url, config))

const postParsed = async <T>(
  url: string,
  body: unknown,
  schema: { parse: (value: unknown) => T },
  config?: AxiosRequestConfig,
): Promise<T> => schema.parse(await apiHelpers.post<unknown>(url, body, config))

export interface AgomCapabilityQuery {
  projectId: string
  entityType: string
  entityId: string
}

export interface AgomAuthorityQuery {
  organizationId: string
  projectId?: string | null
  entityType?: string
  entityId?: string
}

export interface AgomWorkQueueQuery {
  projectId?: string
  sourceType?: AgomWorkSourceType
  claimState?: AgomWorkClaimState | 'mine'
  limit?: number
}

const workMutation = async (
  operation: 'claim' | 'renew',
  sourceType: AgomWorkSourceType,
  sourceId: string,
  input: AgomWorkLeaseMutationInput,
) => {
  const normalizedSourceType = AgomWorkSourceTypeSchema.parse(sourceType)
  const body = AgomWorkLeaseMutationInputSchema.parse(input)
  return postParsed(
    `/work-queue/${encodeSegment(normalizedSourceType)}/${encodeSegment(sourceId)}/${operation}`,
    body,
    AgomWorkMutationSchema,
  )
}

export const agomApi = {
  contracts: () =>
    getParsed('/assurance/governance/contracts', AgomContractRegistrySchema),

  contract: (actionId: string) =>
    getParsed(
      `/assurance/governance/contracts/${encodeSegment(actionId)}`,
      AgomActionContractSchema,
    ),

  capabilities: ({ projectId, entityType, entityId }: AgomCapabilityQuery) =>
    getParsed(
      `/assurance/governance/capabilities/${encodeSegment(entityType)}/${encodeSegment(entityId)}`,
      AgomAuthoritativeCapabilityManifestSchema,
      { params: { project_id: projectId } },
    ),

  createActionRequest: (input: AgomActionRequestInput) => {
    const body = AgomActionRequestInputSchema.parse(input)
    return postParsed(
      '/assurance/governance/actions/requests',
      body,
      AgomActionRequestSchema,
    )
  },

  executeAction: (input: AgomActionExecutionInput) => {
    const body = AgomActionExecutionInputSchema.parse(input)
    return postParsed(
      '/assurance/governance/actions/execute',
      body,
      AgomActionExecutionSchema,
    )
  },

  actorAuthority: ({
    organizationId,
    projectId = null,
    entityType = '',
    entityId = '',
  }: AgomAuthorityQuery) =>
    getParsed(
      '/assurance/governance/responsibilities/authority',
      AgomActorAuthoritySchema,
      {
        params: {
          organization_id: organizationId,
          project_id: projectId || undefined,
          entity_type: entityType,
          entity_id: entityId,
        },
      },
    ),

  responsibilityChain: (organizationId: string) =>
    getParsed(
      '/assurance/governance/responsibilities/chain',
      AgomResponsibilityChainSchema,
      { params: { organization_id: organizationId } },
    ),

  grantResponsibility: (input: AgomResponsibilityGrantInput) => {
    const body = AgomResponsibilityGrantInputSchema.parse(input)
    return postParsed(
      '/assurance/governance/responsibilities/grants',
      body,
      AgomResponsibilityAssignmentSchema,
    )
  },

  revokeResponsibility: (
    assignmentId: string,
    input: AgomResponsibilityRevokeInput,
  ) => {
    const body = AgomResponsibilityRevokeInputSchema.parse(input)
    return postParsed(
      `/assurance/governance/responsibilities/${encodeSegment(assignmentId)}/revoke`,
      body,
      AgomResponsibilityRevocationSchema,
    )
  },

  workQueue: ({
    projectId,
    sourceType,
    claimState,
    limit,
  }: AgomWorkQueueQuery = {}) =>
    getParsed('/work-queue', AgomWorkQueueSchema, {
      params: {
        project_id: projectId,
        source_type: sourceType,
        claim_state: claimState,
        limit,
      },
    }),

  claimWork: (
    sourceType: AgomWorkSourceType,
    sourceId: string,
    input: AgomWorkLeaseMutationInput,
  ) => workMutation('claim', sourceType, sourceId, input),

  renewWork: (
    sourceType: AgomWorkSourceType,
    sourceId: string,
    input: AgomWorkLeaseMutationInput,
  ) => workMutation('renew', sourceType, sourceId, input),

  releaseWork: async (
    sourceType: AgomWorkSourceType,
    sourceId: string,
    input: AgomWorkReleaseMutationInput,
  ) => {
    const normalizedSourceType = AgomWorkSourceTypeSchema.parse(sourceType)
    const body = AgomWorkReleaseMutationInputSchema.parse(input)
    return postParsed(
      `/work-queue/${encodeSegment(normalizedSourceType)}/${encodeSegment(sourceId)}/release`,
      body,
      AgomWorkMutationSchema,
    )
  },
} as const
