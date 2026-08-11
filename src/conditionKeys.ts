import { findConditionKey } from '@cloud-copilot/iam-data'
import { loadPolicy, type Statement } from '@cloud-copilot/iam-policy'
import { isAwsResourceInfoExcludedAction } from '@cloud-copilot/iam-utils'
import {
  globalConditionKeyScenarioMetadata,
  type GlobalConditionKeyScenarioMetadata
} from './globalConditionKeyMetadata.js'
import {
  type JsonPolicyDocument,
  type TruthTableDiagnostic,
  type TruthTablePolicyType,
  type TruthTableValueType
} from './types.js'

/** Generated request model used to decide condition-key scenario availability. */
export type TruthTableRequestModel = 'generatedSignedScpRequest' | 'generatedSignedRcpRequest'

/** Request context used when resolving scenario metadata. */
export interface ScenarioMetadataRequestContext {
  /** Policy type being evaluated. */
  policyType: TruthTablePolicyType

  /** Generated request model being simulated. */
  requestModel: TruthTableRequestModel

  /** IAM action being simulated. */
  action: string

  /** IAM resource being simulated. */
  resource: string
}

const DEFAULT_SCENARIO_METADATA_REQUEST_CONTEXT: ScenarioMetadataRequestContext = {
  policyType: 'scp',
  requestModel: 'generatedSignedScpRequest',
  action: '*',
  resource: '*'
}

/** Internal representation of a policy condition key and the values referenced in the policy. */
export interface ExtractedConditionKey {
  /** Condition key as written in the policy. */
  key: string

  /** Condition operators used with this key. */
  operators: string[]

  /** Condition values referenced by this key in the policy. */
  values: string[]

  /** Policy paths where the condition key appears. */
  paths: string[]
}

/** Metadata used to generate scenario values for a condition key. */
export interface ConditionKeyScenarioMetadata {
  /** Condition key being described. */
  key: string

  /** Human-readable label for output. */
  label: string

  /** Truth-table value type for output cells. */
  valueType: TruthTableValueType

  /** Whether a missing-key scenario should be generated. */
  includeMissing: boolean

  /** Whether the condition key can have multiple request-context values. */
  supportsMultipleValues: boolean

  /** Whether generated scenarios should only include an omitted context key. */
  onlyMissing: boolean
}

/**
 * Extracts unique condition keys and referenced values from all statements in a policy.
 *
 * @param policyDocument - Parsed IAM policy JSON document to inspect.
 * @returns Unique condition-key records in policy encounter order.
 */
export function extractConditionKeys(policyDocument: JsonPolicyDocument): ExtractedConditionKey[] {
  return extractConditionKeysFromStatements(loadPolicy(policyDocument).statements())
}

/**
 * Extracts unique condition keys and referenced values from the provided statements.
 *
 * @param statements - Policy statements to inspect.
 * @returns Unique condition-key records in statement encounter order.
 */
export function extractConditionKeysFromStatements(
  statements: Statement[]
): ExtractedConditionKey[] {
  const keys = new Map<string, ExtractedConditionKey>()
  for (const statement of statements) {
    for (const condition of statement.conditions()) {
      const key = condition.conditionKey()
      const mapKey = key.toLowerCase()
      const existing = keys.get(mapKey) ?? {
        key,
        operators: [],
        values: [],
        paths: []
      }
      existing.operators.push(condition.operation().value())
      existing.values.push(...condition.conditionValues())
      existing.paths.push(condition.keyPath())
      keys.set(mapKey, {
        ...existing,
        operators: [...new Set(existing.operators)],
        values: [...new Set(existing.values)]
      })
    }
  }
  return [...keys.values()]
}

/**
 * Resolves best-effort scenario metadata for an extracted condition key.
 *
 * @param conditionKey - Extracted condition-key record from the policy.
 * @returns Metadata and non-fatal diagnostics for scenario generation.
 */
export async function metadataForConditionKey(
  conditionKey: ExtractedConditionKey,
  requestContext: ScenarioMetadataRequestContext = DEFAULT_SCENARIO_METADATA_REQUEST_CONTEXT
): Promise<{
  metadata: ConditionKeyScenarioMetadata
  diagnostics: TruthTableDiagnostic[]
}> {
  const found = await findConditionKey(conditionKey.key)
  const diagnostics: TruthTableDiagnostic[] = []
  if (!found) {
    diagnostics.push({
      severity: 'info',
      code: 'UNSUPPORTED_CONDITION_KEY',
      message: `Condition key ${conditionKey.key} was not found in iam-data; using generic scenario values.`,
      conditionKey: conditionKey.key,
      path: conditionKey.paths[0]
    })
  }

  return {
    metadata: {
      key: conditionKey.key,
      label: labelForConditionKey(conditionKey.key),
      valueType:
        applicableGlobalConditionKeyMetadata(conditionKey.key, requestContext)?.valueType ??
        valueTypeForIamType(found?.type),
      includeMissing: shouldIncludeMissingScenario(conditionKey, requestContext),
      supportsMultipleValues: supportsMultipleValuesForIamType(found?.type),
      onlyMissing: shouldOnlyGenerateMissingScenario(conditionKey, requestContext)
    },
    diagnostics
  }
}

/**
 * Converts an IAM condition-key type into a truth-table value type.
 *
 * @param iamType - IAM condition-key type from iam-data.
 * @returns Truth-table value type for output cells.
 */
export function valueTypeForIamType(iamType: string | undefined): TruthTableValueType {
  const normalized = iamType?.toLowerCase()
  if (normalized === 'bool') {
    return 'boolean'
  }
  if (normalized === 'numeric') {
    return 'number'
  }
  if (normalized === 'arn') {
    return 'arn'
  }
  if (normalized === 'ipaddress') {
    return 'ip'
  }
  if (normalized === 'date') {
    return 'date'
  }
  if (normalized === 'string' || normalized === 'arrayofstring') {
    return 'string'
  }
  return 'unknown'
}

/**
 * Determines whether an IAM condition-key type supports multiple request-context values.
 *
 * @param iamType - IAM condition-key type from iam-data.
 * @returns True when the condition key can have multiple values in request context.
 */
export function supportsMultipleValuesForIamType(iamType: string | undefined): boolean {
  return iamType?.toLowerCase().startsWith('arrayof') ?? false
}

/**
 * Determines whether missing-key scenarios should be included for a condition key.
 *
 * @param conditionKey - Extracted condition-key record from the policy.
 * @returns True when generated scenarios should include an omitted context key.
 */
export function shouldIncludeMissingScenario(
  conditionKey: ExtractedConditionKey,
  requestContext: ScenarioMetadataRequestContext = DEFAULT_SCENARIO_METADATA_REQUEST_CONTEXT
): boolean {
  if (rcpPrincipalKeyCanBeMissing(conditionKey.key, requestContext)) {
    return true
  }

  const resourceInfoAvailability = resourceInfoKeyAvailability(conditionKey.key, requestContext)
  if (resourceInfoAvailability === 'present') {
    return conditionKey.key.toLowerCase() !== 'aws:resourceaccount'
  }
  if (resourceInfoAvailability === 'missing') {
    return true
  }

  const globalMetadata = applicableGlobalConditionKeyMetadata(conditionKey.key, requestContext)
  if (globalMetadata) {
    return globalMetadata.canBeMissing
  }
  return true
}

/**
 * Determines whether scenario generation should only include the missing-key case.
 *
 * @param conditionKey - Extracted condition-key record from the policy.
 * @returns True when present values should not be generated for this request model.
 */
export function shouldOnlyGenerateMissingScenario(
  conditionKey: ExtractedConditionKey,
  requestContext: ScenarioMetadataRequestContext = DEFAULT_SCENARIO_METADATA_REQUEST_CONTEXT
): boolean {
  if (resourceInfoKeyAvailability(conditionKey.key, requestContext) === 'missing') {
    return true
  }
  return (
    applicableGlobalConditionKeyMetadata(conditionKey.key, requestContext)?.scenarioValueMode ===
    'missingOnly'
  )
}

/** Resource-info context key availability for the generated request. */
type ResourceInfoKeyAvailability = 'present' | 'missing' | 'notResourceInfoKey'

/**
 * Resolves global condition-key metadata only when it applies to the generated request model.
 *
 * @param conditionKey - Condition key to inspect.
 * @param requestContext - Generated request context metadata.
 * @returns Applicable metadata, or undefined when scoped metadata does not apply.
 */
function applicableGlobalConditionKeyMetadata(
  conditionKey: string,
  requestContext: ScenarioMetadataRequestContext
): GlobalConditionKeyScenarioMetadata | undefined {
  const metadata = globalConditionKeyScenarioMetadata(conditionKey)
  if (!metadata) {
    return undefined
  }
  if (metadata.presenceScope === 'allRequests') {
    return metadata
  }
  if (metadata.presenceScope === 'generatedSignedRequests') {
    return requestContext.requestModel === 'generatedSignedScpRequest' ||
      requestContext.requestModel === 'generatedSignedRcpRequest'
      ? metadata
      : undefined
  }
  if (metadata.presenceScope === 'generatedScpRequests') {
    return requestContext.requestModel === 'generatedSignedScpRequest' ? metadata : undefined
  }
  if (metadata.presenceScope === 'generatedRcpRequests') {
    return requestContext.requestModel === 'generatedSignedRcpRequest' ? metadata : undefined
  }
  return undefined
}

/**
 * Determines resource-information key availability for the generated request.
 *
 * @param conditionKey - Condition key to inspect.
 * @param requestContext - Generated request context metadata.
 * @returns Availability for resource-info keys, or `notResourceInfoKey` for other keys.
 */
function resourceInfoKeyAvailability(
  conditionKey: string,
  requestContext: ScenarioMetadataRequestContext
): ResourceInfoKeyAvailability {
  const key = conditionKey.toLowerCase()
  if (!['aws:resourceaccount', 'aws:resourceorgid', 'aws:resourceorgpaths'].includes(key)) {
    return 'notResourceInfoKey'
  }
  if (requestContext.requestModel !== 'generatedSignedRcpRequest') {
    return 'notResourceInfoKey'
  }
  return isAwsResourceInfoExcludedAction(requestContext.action) ? 'missing' : 'present'
}

/**
 * Determines whether a principal-related key should include missing scenarios for RCPs.
 *
 * RCPs can evaluate resource requests where principal organization/account details are absent,
 * such as anonymous requests. SCP-generated requests keep their existing signed-principal behavior.
 *
 * @param conditionKey - Condition key to inspect.
 * @param requestContext - Generated request context metadata.
 * @returns True when the key should include a missing scenario for generated RCP requests.
 */
function rcpPrincipalKeyCanBeMissing(
  conditionKey: string,
  requestContext: ScenarioMetadataRequestContext
): boolean {
  if (requestContext.requestModel !== 'generatedSignedRcpRequest') {
    return false
  }
  return [
    'aws:principalaccount',
    'aws:principalarn',
    'aws:principalorgid',
    'aws:principalorgpaths',
    'aws:userid'
  ].includes(conditionKey.toLowerCase())
}

/**
 * Builds a readable label from a condition key.
 *
 * @param key - Condition key to label.
 * @returns Human-readable label for table output.
 */
function labelForConditionKey(key: string): string {
  const knownLabels: Record<string, string> = {
    'aws:resourceorgid': 'Resource Org ID',
    'aws:viaawsservice': 'Is Via Service?',
    'aws:principalorgid': 'Principal Org ID',
    'aws:principalisawsservice': 'Is AWS Service Principal?',
    'aws:resourceorgpaths': 'Resource Org Paths',
    'aws:principalorgpaths': 'Principal Org Paths'
  }
  return knownLabels[key.toLowerCase()] ?? key
}
