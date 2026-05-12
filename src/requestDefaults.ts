import { expandIamActions, invertIamActions } from '@cloud-copilot/iam-expand'
import { loadPolicy } from '@cloud-copilot/iam-policy'
import { type JsonPolicyDocument, type TruthTableDiagnostic } from './types.js'

/** Default resource used for generated simulations. */
export const DEFAULT_RESOURCE = '*'

/** Default principal used for generated simulations. */
export const DEFAULT_PRINCIPAL = 'arn:aws:iam::111111111111:role/TestRole'

/** Baseline request values used for scenario simulation. */
export interface BaselineRequest {
  /** IAM action to simulate. */
  action: string

  /** IAM resource to simulate. */
  resource: string

  /** Principal ARN to simulate. */
  principal: string
}

/** Result of resolving baseline request defaults and overrides. */
export type ResolveBaselineRequestResult =
  | { resultType: 'success'; request: BaselineRequest }
  | { resultType: 'unsupported'; diagnostics: TruthTableDiagnostic[] }

/**
 * Resolves simulation baseline request values from caller overrides and deterministic defaults.
 *
 * @param policyDocument - Parsed IAM policy JSON document used for default action inference.
 * @param overrides - Optional caller-provided request values.
 * @returns Baseline request values or diagnostics when defaults cannot be inferred.
 */
export async function resolveBaselineRequest(
  policyDocument: JsonPolicyDocument,
  overrides: Partial<BaselineRequest> | undefined
): Promise<ResolveBaselineRequestResult> {
  const action = overrides?.action ?? (await defaultAction(policyDocument))
  if (!action) {
    return {
      resultType: 'unsupported',
      diagnostics: [
        {
          severity: 'error',
          code: 'REQUEST_DEFAULT_UNSUPPORTED',
          message:
            'Unable to determine a default action from the first statement. Provide --action.'
        }
      ]
    }
  }

  return {
    resultType: 'success',
    request: {
      action,
      resource: overrides?.resource ?? DEFAULT_RESOURCE,
      principal: overrides?.principal ?? DEFAULT_PRINCIPAL
    }
  }
}

/**
 * Infers a default action from the first policy statement.
 *
 * @param policyDocument - Parsed IAM policy JSON document to inspect.
 * @returns The first expanded action, or undefined if no action can be inferred.
 */
export async function defaultAction(
  policyDocument: JsonPolicyDocument
): Promise<string | undefined> {
  const firstStatement = loadPolicy(policyDocument).statements()[0]
  if (!firstStatement) {
    return undefined
  }

  if (firstStatement.isActionStatement()) {
    const actions = firstStatement.actions().map((action) => action.value())
    return firstExpandedAction(actions)
  }

  if (firstStatement.isNotActionStatement()) {
    const notActions = firstStatement.notActions().map((action) => action.value())
    const inverted = await invertIamActions(notActions)
    return inverted[0]
  }

  return undefined
}

/**
 * Expands action strings and returns the first concrete action.
 *
 * @param actions - Action strings to expand.
 * @returns The first expanded action, or undefined if expansion yields no values.
 */
async function firstExpandedAction(actions: string[]): Promise<string | undefined> {
  const expanded = await expandIamActions(actions, {
    expandAsterisk: true,
    errorOnInvalidFormat: false,
    errorOnInvalidService: false
  })
  return expanded[0]
}
