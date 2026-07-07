import { type TruthTableValueType } from './types.js'

/** Request-context scope where global condition-key presence metadata applies. */
export type GlobalConditionKeyPresenceScope =
  'allRequests' | 'generatedSignedRequests' | 'generatedScpRequests' | 'generatedRcpRequests'

/** Scenario value generation mode for a global IAM condition key. */
export type GlobalConditionKeyScenarioValueMode = 'standard' | 'missingOnly'

/** Scenario-generation metadata for a global IAM condition key. */
export interface GlobalConditionKeyScenarioMetadata {
  /** Canonical global condition key name. */
  key: string

  /** Whether the key can be absent from request context in the supported scope. */
  canBeMissing: boolean

  /** Request-context scope where `canBeMissing` is known to apply. */
  presenceScope: GlobalConditionKeyPresenceScope

  /** How scenario values should be generated for the supported request-context scope. */
  scenarioValueMode?: GlobalConditionKeyScenarioValueMode

  /** Optional truth-table value type override for corrected generated scenario output. */
  valueType?: TruthTableValueType
}

const globalConditionKeyScenarioMetadataByKey: Record<string, GlobalConditionKeyScenarioMetadata> =
  {
    'aws:principalaccount': {
      key: 'aws:PrincipalAccount',
      canBeMissing: false,
      presenceScope: 'generatedSignedRequests'
    },
    'aws:principalarn': {
      key: 'aws:PrincipalArn',
      canBeMissing: false,
      presenceScope: 'generatedSignedRequests'
    },
    'aws:assumedroot': {
      key: 'aws:AssumedRoot',
      canBeMissing: true,
      presenceScope: 'generatedScpRequests',
      valueType: 'boolean'
    },
    'aws:principalorgid': {
      key: 'aws:PrincipalOrgID',
      canBeMissing: false,
      presenceScope: 'generatedScpRequests'
    },
    'aws:principalorgpaths': {
      key: 'aws:PrincipalOrgPaths',
      canBeMissing: false,
      presenceScope: 'generatedScpRequests'
    },
    'aws:principalisawsservice': {
      key: 'aws:PrincipalIsAWSService',
      canBeMissing: false,
      presenceScope: 'generatedSignedRequests'
    },
    'aws:principaltype': {
      key: 'aws:PrincipalType',
      canBeMissing: false,
      presenceScope: 'allRequests'
    },
    'aws:userid': {
      key: 'aws:userid',
      canBeMissing: false,
      presenceScope: 'allRequests'
    },
    'aws:viaawsservice': {
      key: 'aws:ViaAWSService',
      canBeMissing: false,
      presenceScope: 'allRequests'
    },
    'aws:currenttime': {
      key: 'aws:CurrentTime',
      canBeMissing: false,
      presenceScope: 'allRequests'
    },
    'aws:epochtime': {
      key: 'aws:EpochTime',
      canBeMissing: false,
      presenceScope: 'allRequests'
    },
    'aws:requestedregion': {
      key: 'aws:RequestedRegion',
      canBeMissing: false,
      presenceScope: 'allRequests'
    },
    'aws:sourceaccount': {
      key: 'aws:SourceAccount',
      canBeMissing: true,
      presenceScope: 'generatedScpRequests',
      scenarioValueMode: 'missingOnly'
    },
    'aws:sourcearn': {
      key: 'aws:SourceArn',
      canBeMissing: true,
      presenceScope: 'generatedScpRequests',
      scenarioValueMode: 'missingOnly'
    },
    'aws:sourceowner': {
      key: 'aws:SourceOwner',
      canBeMissing: true,
      presenceScope: 'generatedScpRequests',
      scenarioValueMode: 'missingOnly'
    },
    'aws:sourceorgid': {
      key: 'aws:SourceOrgID',
      canBeMissing: true,
      presenceScope: 'generatedScpRequests',
      scenarioValueMode: 'missingOnly'
    },
    'aws:sourceorgpaths': {
      key: 'aws:SourceOrgPaths',
      canBeMissing: true,
      presenceScope: 'generatedScpRequests',
      scenarioValueMode: 'missingOnly'
    },
    'aws:securetransport': {
      key: 'aws:SecureTransport',
      canBeMissing: false,
      presenceScope: 'allRequests'
    },
    'aws:useragent': {
      key: 'aws:UserAgent',
      canBeMissing: false,
      presenceScope: 'allRequests'
    }
  }

/**
 * Looks up scenario-generation metadata for a global IAM condition key.
 *
 * @param conditionKey - Condition key to look up, case-insensitive.
 * @returns Global condition-key metadata, or undefined when no metadata is maintained.
 */
export function globalConditionKeyScenarioMetadata(
  conditionKey: string
): GlobalConditionKeyScenarioMetadata | undefined {
  return globalConditionKeyScenarioMetadataByKey[conditionKey.toLowerCase()]
}
