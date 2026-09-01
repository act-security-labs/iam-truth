import { iamActionDetails, iamResourceTypeDetails } from '@actsecurity/iam-data'
import { resourceStringMatchesResourceTypePattern } from '@actsecurity/iam-utils'
import { type TruthTableSupportedResourceType, type TruthTableUntestedResource } from './types.js'

/** Result of validating requested resources against IAM action metadata. */
export type ResourceValidationResult =
  | {
      /** Validation completed using IAM action/resource metadata. */
      resultType: 'validated'

      /** Requested resources that can be tested for the action. */
      testableResources: string[]

      /** Requested resources that cannot be tested for the action. */
      untestedResources: TruthTableUntestedResource[]
    }
  | {
      /** Action or resource metadata was unavailable, so validation was skipped. */
      resultType: 'actionMetadataUnavailable'
    }

/** Parsed concrete IAM action string. */
interface ParsedAction {
  /** IAM service prefix. */
  service: string

  /** IAM action name. */
  action: string
}

/**
 * Validates requested resources against the resource types supported by an IAM action.
 *
 * @param action - Concrete IAM action being tested.
 * @param resources - Requested resources to validate.
 * @returns Partitioned resources, or a metadata-unavailable result when validation should be skipped.
 */
export async function validateResourcesForAction(
  action: string,
  resources: string[]
): Promise<ResourceValidationResult> {
  const parsedAction = parseConcreteAction(action)
  if (!parsedAction) {
    return { resultType: 'actionMetadataUnavailable' }
  }

  const supportedResourceTypes = await supportedResourceTypesForAction(parsedAction)
  if (!supportedResourceTypes) {
    return { resultType: 'actionMetadataUnavailable' }
  }

  const testableResources: string[] = []
  const untestedResources: TruthTableUntestedResource[] = []

  for (const resource of resources) {
    if (resourceCanBeTested(resource, supportedResourceTypes)) {
      testableResources.push(resource)
    } else {
      untestedResources.push({
        resource,
        reason: 'unsupportedForAction',
        action,
        supportedResourceTypes
      })
    }
  }

  return { resultType: 'validated', testableResources, untestedResources }
}

/**
 * Parses a concrete IAM action string into service and action components.
 *
 * @param action - IAM action string to parse.
 * @returns Parsed action, or undefined for malformed or wildcarded action strings.
 */
function parseConcreteAction(action: string): ParsedAction | undefined {
  const parts = action.split(':')
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return undefined
  }
  if (parts[0].includes('*') || parts[1].includes('*')) {
    return undefined
  }
  return { service: parts[0], action: parts[1] }
}

/**
 * Loads supported resource type patterns for an IAM action.
 *
 * @param action - Parsed IAM action.
 * @returns Supported resource type records, or undefined when metadata cannot be loaded.
 */
async function supportedResourceTypesForAction(
  action: ParsedAction
): Promise<TruthTableSupportedResourceType[] | undefined> {
  try {
    const actionDetails = await iamActionDetails(action.service, action.action)
    if (actionDetails.isWildcardOnly || actionDetails.resourceTypes.length === 0) {
      return []
    }

    const supportedResourceTypes: TruthTableSupportedResourceType[] = []
    for (const resourceType of actionDetails.resourceTypes) {
      const details = await iamResourceTypeDetails(action.service, resourceType.name)
      supportedResourceTypes.push({ name: resourceType.name, arnPattern: details.arn })
    }
    return supportedResourceTypes.sort((left, right) => left.name.localeCompare(right.name))
  } catch {
    return undefined
  }
}

/**
 * Checks whether a requested resource can be tested for an action.
 *
 * @param resource - Requested resource string.
 * @param supportedResourceTypes - Resource type patterns supported by the action.
 * @returns True when the resource can be tested.
 */
function resourceCanBeTested(
  resource: string,
  supportedResourceTypes: TruthTableSupportedResourceType[]
): boolean {
  if (supportedResourceTypes.length === 0) {
    return resource === '*'
  }

  return supportedResourceTypes.some((resourceType) =>
    resourceStringMatchesResourceTypePattern(resource, resourceType.arnPattern)
  )
}
