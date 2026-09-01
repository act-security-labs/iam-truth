import { loadPolicy } from '@actsecurity/iam-policy'
import { type JsonPolicyDocument, type TruthTablePolicyEffectMode } from './types.js'

/**
 * Determines whether a policy contains only Allow statements, only Deny statements, or both.
 *
 * @param policyDocument - Parsed IAM policy JSON document to inspect.
 * @returns The effect mode represented by the policy statements.
 */
export function policyEffectMode(policyDocument: JsonPolicyDocument): TruthTablePolicyEffectMode {
  const policy = loadPolicy(policyDocument)
  const statements = policy.statements()
  const hasAllow = statements.some((statement) => statement.isAllow())
  const hasDeny = statements.some((statement) => statement.isDeny())

  if (hasAllow && hasDeny) {
    return 'allowAndDeny'
  }
  if (hasAllow) {
    return 'allowOnly'
  }
  return 'denyOnly'
}

/**
 * Checks whether a policy has at least one Allow statement.
 *
 * @param policyDocument - Parsed IAM policy JSON document to inspect.
 * @returns True when any statement in the policy has an Allow effect.
 */
export function policyHasAllowStatement(policyDocument: JsonPolicyDocument): boolean {
  return loadPolicy(policyDocument)
    .statements()
    .some((statement) => statement.isAllow())
}
