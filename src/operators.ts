import { loadPolicy } from '@cloud-copilot/iam-policy'
import { type JsonPolicyDocument, type TruthTableDiagnostic } from './types.js'

const supportedBaseOperators = new Set([
  'arnequals',
  'arnlike',
  'arnnotequals',
  'arnnotlike',
  'binaryequals',
  'bool',
  'dateequals',
  'datenotequals',
  'datelessthan',
  'datelessthanequals',
  'dategreaterthan',
  'dategreaterthanequals',
  'ipaddress',
  'notipaddress',
  'null',
  'numericequals',
  'numericnotequals',
  'numericlessthan',
  'numericlessthanequals',
  'numericgreaterthan',
  'numericgreaterthanequals',
  'stringequals',
  'stringequalsignorecase',
  'stringlike',
  'stringnotequals',
  'stringnotequalsignorecase',
  'stringnotlike'
])

/** Parsed IAM condition operator components relevant to scenario generation. */
export interface ParsedConditionOperator {
  /** Raw condition operator from the policy. */
  rawOperator: string

  /** Optional set operator prefix. */
  setOperator?: 'ForAnyValue' | 'ForAllValues'

  /** Base operator without set prefix or IfExists suffix. */
  baseOperator: string

  /** Whether the raw operator includes the IfExists suffix. */
  ifExists: boolean
}

/**
 * Parses an IAM condition operator into set, base, and IfExists components.
 *
 * @param rawOperator - Raw condition operator from the policy.
 * @returns Parsed condition operator components.
 */
export function parseConditionOperator(rawOperator: string): ParsedConditionOperator {
  const parts = rawOperator.split(':')
  const operatorPart = parts.at(-1) ?? rawOperator
  const maybeSetOperator = parts.length > 1 ? parts[0] : undefined
  const ifExists = operatorPart.toLowerCase().endsWith('ifexists')
  const baseOperator = ifExists ? operatorPart.slice(0, -'IfExists'.length) : operatorPart

  return {
    rawOperator,
    setOperator:
      maybeSetOperator === 'ForAnyValue' || maybeSetOperator === 'ForAllValues'
        ? maybeSetOperator
        : undefined,
    baseOperator,
    ifExists
  }
}

/**
 * Validates that all policy condition operators are supported by iam-truth scenario generation.
 *
 * @param policyDocument - Parsed IAM policy JSON document to inspect.
 * @returns Error diagnostics for unsupported condition operators.
 */
export function validateConditionOperators(
  policyDocument: JsonPolicyDocument
): TruthTableDiagnostic[] {
  const diagnostics: TruthTableDiagnostic[] = []
  for (const statement of loadPolicy(policyDocument).statements()) {
    for (const condition of statement.conditions()) {
      const parsed = parseConditionOperator(condition.operation().value())
      const rawSetOperator = condition.operation().value().includes(':')
        ? condition.operation().value().split(':')[0]
        : undefined
      if (rawSetOperator && !parsed.setOperator) {
        diagnostics.push({
          severity: 'error',
          code: 'UNSUPPORTED_OPERATOR',
          message: `Unsupported condition set operator ${rawSetOperator}. Supported set operators are ForAnyValue and ForAllValues.`,
          path: condition.operatorKeyPath(),
          conditionKey: condition.conditionKey()
        })
        continue
      }

      if (!supportedBaseOperators.has(parsed.baseOperator.toLowerCase())) {
        diagnostics.push({
          severity: 'error',
          code: 'UNSUPPORTED_OPERATOR',
          message: `Unsupported condition operator ${condition.operation().value()}. iam-truth supports standard string, ARN, numeric, date, boolean, binary, IP address, and Null operators.`,
          path: condition.operatorKeyPath(),
          conditionKey: condition.conditionKey()
        })
      }
    }
  }
  return diagnostics
}

/**
 * Checks whether an operator is a negated IAM condition operator.
 *
 * @param baseOperator - Base operator without set prefix or IfExists suffix.
 * @returns True when the operator is a Not/negated operator.
 */
export function isNegatedOperator(baseOperator: string): boolean {
  return baseOperator.toLowerCase().includes('not')
}
