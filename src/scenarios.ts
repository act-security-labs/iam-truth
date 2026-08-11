import {
  type ConditionKeyScenarioMetadata,
  type ExtractedConditionKey,
  metadataForConditionKey,
  type ScenarioMetadataRequestContext
} from './conditionKeys.js'
import { fakeConditionKeyValue, firstDistinctString } from './conditionKeyFakeValues.js'
import { filterCompatibleContextKeyRows } from './contextKeyCompatibility.js'
import { parseConditionOperator, type ParsedConditionOperator } from './operators.js'
import { type TruthTableCellValue, type TruthTableDiagnostic } from './types.js'

/** A generated context value candidate for one condition key. */
export interface ScenarioValue {
  /** Cell value to display in the truth table. */
  cellValue: TruthTableCellValue

  /** Context value to pass to iam-simulate. Undefined means the key is omitted. */
  contextValue: string | string[] | undefined
}

/** A generated scenario before simulation. */
export interface GeneratedScenario {
  /** Stable scenario identifier. */
  scenarioId: string

  /** Display cells for condition-key columns. */
  cells: Record<string, TruthTableCellValue>

  /** Request context variables for simulation. */
  context: Record<string, string | string[]>
}

/** Options controlling low-level scenario generation. */
export interface ScenarioGenerationOptions {
  /** Optional allow list of condition keys to include. */
  targetConditionKeys?: string[]

  /** Whether to generate matching examples for every policy value. */
  showExamplesForAllPolicyValues?: boolean

  /** Generated request context used to resolve condition-key presence metadata. */
  requestContext?: ScenarioMetadataRequestContext
}

/** Metadata and scenarios generated from policy condition keys. */
export interface ScenarioGenerationResult {
  /** Condition-key metadata used to build columns. */
  metadata: ConditionKeyScenarioMetadata[]

  /** Generated scenarios. */
  scenarios: GeneratedScenario[]

  /** Non-fatal diagnostics emitted while generating scenarios. */
  diagnostics: TruthTableDiagnostic[]
}

/**
 * Generates scenario combinations for extracted condition keys.
 *
 * @param conditionKeys - Condition keys extracted from the input policy.
 * @param options - Optional scenario generation controls.
 * @returns Scenario metadata, generated scenarios, and diagnostics.
 */
export async function generateScenarios(
  conditionKeys: ExtractedConditionKey[],
  options?: ScenarioGenerationOptions | string[]
): Promise<ScenarioGenerationResult> {
  const scenarioOptions = Array.isArray(options) ? { targetConditionKeys: options } : options
  const targetSet = scenarioOptions?.targetConditionKeys
    ? new Set(scenarioOptions.targetConditionKeys.map((key) => key.toLowerCase()))
    : undefined
  const keys = targetSet
    ? conditionKeys.filter((conditionKey) => targetSet.has(conditionKey.key.toLowerCase()))
    : conditionKeys

  const metadata: ConditionKeyScenarioMetadata[] = []
  const diagnostics: TruthTableDiagnostic[] = []
  const valueSets: Array<{ key: string; values: ScenarioValue[] }> = []

  for (const conditionKey of keys) {
    const result = await metadataForConditionKey(conditionKey, scenarioOptions?.requestContext)
    metadata.push(result.metadata)
    diagnostics.push(...result.diagnostics)
    valueSets.push({
      key: conditionKey.key,
      values: valuesForConditionKey(conditionKey, result.metadata, scenarioOptions)
    })
  }

  const scenarios = cartesianScenarios(valueSets)
  return { metadata, scenarios, diagnostics }
}

/**
 * Generates deterministic candidate values for one condition key.
 *
 * @param conditionKey - Extracted condition-key policy values.
 * @param metadata - Scenario metadata for the key.
 * @returns Candidate values for scenario generation.
 */
export function valuesForConditionKey(
  conditionKey: ExtractedConditionKey,
  metadata: ConditionKeyScenarioMetadata,
  options?: Pick<ScenarioGenerationOptions, 'showExamplesForAllPolicyValues'>
): ScenarioValue[] {
  const values: ScenarioValue[] = []
  const parsedOperator = parseConditionOperator(conditionKey.operators[0] ?? 'StringEquals')

  if (metadata.onlyMissing) {
    values.push({ cellValue: null, contextValue: undefined })
    return uniqueScenarioValues(values)
  }

  if (parsedOperator.baseOperator.toLowerCase() === 'null') {
    values.push(...nullOperatorValues(conditionKey, metadata))
    return uniqueScenarioValues(values)
  }

  if (metadata.supportsMultipleValues && parsedOperator.setOperator) {
    values.push(...multiValueSetOperatorValues(conditionKey, metadata, parsedOperator, options))
    return uniqueScenarioValues(values)
  }

  if (metadata.valueType === 'number' && isNumericComparisonOperator(parsedOperator.baseOperator)) {
    values.push(...numericComparisonValues(conditionKey, options))
  } else {
    for (const policyValue of policyValuesForScenarioGeneration(conditionKey, options)) {
      values.push(matchingValueFromString(policyValue, metadata, parsedOperator.baseOperator))
    }

    values.push(alternateValue(conditionKey, metadata, parsedOperator.baseOperator))
  }
  if (metadata.includeMissing) {
    values.push({ cellValue: null, contextValue: undefined })
  }

  return uniqueScenarioValues(values)
}

/**
 * Converts a policy string value into a typed scenario value.
 *
 * @param value - Policy condition value.
 * @param metadata - Scenario metadata for the condition key.
 * @returns Scenario value for the policy value.
 */
function matchingValueFromString(
  value: string,
  metadata: ConditionKeyScenarioMetadata,
  baseOperator: string
): ScenarioValue {
  const operator = baseOperator.toLowerCase()
  if (metadata.valueType === 'boolean') {
    const boolValue = value.toLowerCase() === 'true'
    return { cellValue: boolValue, contextValue: String(boolValue) }
  }
  if (metadata.valueType === 'number') {
    return numericValueForOperator(Number(value), operator, true)
  }
  if (metadata.valueType === 'date') {
    return dateValueForOperator(value, operator, true)
  }
  if (metadata.valueType === 'ip') {
    const ipValue = sampleIpForOperator(operator, true)
    return { cellValue: ipValue, contextValue: ipValue }
  }
  if (operator.includes('like')) {
    const likeValue = operator.includes('arn')
      ? matchingArnLikeValue(value)
      : matchingLikeValue(value)
    return { cellValue: likeValue, contextValue: likeValue }
  }
  return { cellValue: value, contextValue: value }
}

/**
 * Generates multivalue request-context arrays for a set condition operator.
 *
 * @param conditionKey - Extracted condition-key policy values.
 * @param metadata - Scenario metadata for the key.
 * @param operator - Parsed condition operator with a set-operator prefix.
 * @returns Scenario values that exercise none, partial, and complete matching.
 */
function multiValueSetOperatorValues(
  conditionKey: ExtractedConditionKey,
  metadata: ConditionKeyScenarioMetadata,
  operator: ParsedConditionOperator,
  options?: Pick<ScenarioGenerationOptions, 'showExamplesForAllPolicyValues'>
): ScenarioValue[] {
  const matchingValues = policyValuesForScenarioGeneration(conditionKey, options).map((value) =>
    String(matchingValueFromString(value, metadata, operator.baseOperator).contextValue)
  )
  const firstMatching =
    matchingValues[0] ??
    fakeConditionKeyValue({
      conditionKey: conditionKey.key,
      valueType: metadata.valueType,
      existingValues: conditionKey.values,
      role: 'matchingFallback'
    })
  const alternate = String(
    alternateValue(conditionKey, metadata, operator.baseOperator).contextValue
  )
  const allMatching = matchingValues.length > 0 ? matchingValues : [firstMatching]
  const values: ScenarioValue[] = [
    { cellValue: [alternate], contextValue: [alternate] },
    {
      cellValue: [firstMatching, alternate],
      contextValue: [firstMatching, alternate]
    },
    { cellValue: allMatching, contextValue: allMatching }
  ]

  if (metadata.includeMissing) {
    values.push({ cellValue: null, contextValue: undefined })
  }

  return values
}

/**
 * Creates an alternate non-policy value for a condition key.
 *
 * @param conditionKey - Extracted condition-key policy values.
 * @param metadata - Scenario metadata for the condition key.
 * @param baseOperator - Base condition operator used to choose a meaningful alternate.
 * @returns Alternate scenario value.
 */
function alternateValue(
  conditionKey: ExtractedConditionKey,
  metadata: ConditionKeyScenarioMetadata,
  baseOperator: string
): ScenarioValue {
  const operator = baseOperator.toLowerCase()
  if (metadata.valueType === 'boolean') {
    const firstValue = conditionKey.values[0]?.toLowerCase() === 'true'
    return { cellValue: !firstValue, contextValue: String(!firstValue) }
  }
  if (metadata.valueType === 'number') {
    return numericValueForOperator(Number(conditionKey.values[0] ?? '1'), operator, false)
  }
  if (metadata.valueType === 'date') {
    return dateValueForOperator(conditionKey.values[0] ?? '2024-01-01T00:00:00Z', operator, false)
  }
  if (metadata.valueType === 'ip') {
    const ipValue = sampleIpForOperator(operator, false)
    return { cellValue: ipValue, contextValue: ipValue }
  }
  if (operator.includes('like') && !operator.includes('arn')) {
    return nonMatchingLikeValue(conditionKey)
  }

  const value = fakeConditionKeyValue({
    conditionKey: conditionKey.key,
    valueType: metadata.valueType,
    existingValues: conditionKey.values,
    role: 'alternate'
  })
  return {
    cellValue: value,
    contextValue: metadata.supportsMultipleValues ? [value] : value
  }
}

/**
 * Creates a deterministic string value intended not to match any Like policy pattern.
 *
 * @param conditionKey - Extracted condition-key policy values.
 * @returns A scenario value outside the policy Like pattern set.
 */
function nonMatchingLikeValue(conditionKey: ExtractedConditionKey): ScenarioValue {
  const value = firstNonMatchingLikeValue(conditionKey.values)
  return { cellValue: value, contextValue: value }
}

/**
 * Creates a deterministic string value intended to match an IAM StringLike pattern.
 *
 * @param pattern - IAM StringLike pattern using `*` and `?` wildcards.
 * @returns A concrete value that should match the pattern.
 */
export function matchingLikeValue(pattern: string): string {
  const value = pattern.replace(/\*/g, 'example').replace(/\?/g, 'x')
  return value.length > 0 ? value : 'example'
}

/**
 * Creates a deterministic string value intended to match an IAM ArnLike pattern.
 *
 * @param pattern - IAM ArnLike pattern using `*` and `?` wildcards.
 * @returns A concrete ARN-like value that should match the pattern.
 */
function matchingArnLikeValue(pattern: string): string {
  if (!pattern.toLowerCase().startsWith('arn:')) {
    return matchingLikeValue(pattern)
  }

  const arnParts = pattern.split(':')
  const accountIdIndex = 4
  if (arnParts[accountIdIndex] && /^\*+$/.test(arnParts[accountIdIndex])) {
    arnParts[accountIdIndex] = '111111111111'
  }
  return matchingLikeValue(arnParts.join(':'))
}

/**
 * Creates a present value for Null-operator scenario generation.
 *
 * @param conditionKey - Extracted condition-key policy values.
 * @param metadata - Scenario metadata used to choose a present value shape.
 * @returns Present scenario value for the condition key.
 */
function nullOperatorPresentValue(
  conditionKey: ExtractedConditionKey,
  metadata: ConditionKeyScenarioMetadata
): ScenarioValue {
  if (metadata.valueType === 'boolean') {
    return { cellValue: true, contextValue: 'true' }
  }

  const presentContextValue = fakeConditionKeyValue({
    conditionKey: conditionKey.key,
    valueType: metadata.valueType,
    existingValues: conditionKey.values,
    role: 'present'
  })
  return {
    cellValue: presentContextValue,
    contextValue: metadata.supportsMultipleValues ? [presentContextValue] : presentContextValue
  }
}

/**
 * Creates a deterministic string value that does not match any provided IAM StringLike pattern.
 *
 * @param patterns - IAM StringLike patterns to avoid matching.
 * @returns A concrete value that does not match the patterns when one can be found.
 */
export function firstNonMatchingLikeValue(patterns: string[]): string {
  const candidates = nonMatchingLikeCandidates(patterns)
  return (
    candidates.find((candidate) => !matchesAnyLikePattern(candidate, patterns)) ??
    firstDistinctString(patterns, ['does-not-match-cloud-copilot-pattern'])
  )
}

/**
 * Checks whether a value matches any IAM StringLike pattern.
 *
 * @param value - Concrete request-context value.
 * @param patterns - IAM StringLike patterns to test.
 * @returns True when at least one pattern matches the value.
 */
export function matchesAnyLikePattern(value: string, patterns: string[]): boolean {
  return patterns.some((pattern) => matchesLikePattern(value, pattern))
}

/**
 * Checks whether a value matches an IAM StringLike pattern.
 *
 * @param value - Concrete request-context value.
 * @param pattern - IAM StringLike pattern using `*` and `?` wildcards.
 * @returns True when the value matches the pattern.
 */
export function matchesLikePattern(value: string, pattern: string): boolean {
  return likePatternRegex(pattern).test(value)
}

/**
 * Builds candidate values likely to avoid the provided IAM StringLike patterns.
 *
 * @param patterns - IAM StringLike patterns to avoid matching.
 * @returns Candidate non-matching values in deterministic priority order.
 */
function nonMatchingLikeCandidates(patterns: string[]): string[] {
  return uniqueStrings([
    ...patterns.map((pattern) => `not-${matchingLikeValue(pattern)}`),
    ...patterns.map((pattern) => `${matchingLikeValue(pattern)}-not`),
    'does-not-match-cloud-copilot-pattern',
    'definitely-not-a-policy-match',
    'zzzz-non-matching-value',
    'x',
    ''
  ])
}

/**
 * Converts an IAM StringLike pattern to an anchored regular expression.
 *
 * @param pattern - IAM StringLike pattern using `*` and `?` wildcards.
 * @returns Regular expression that implements the wildcard match.
 */
function likePatternRegex(pattern: string): RegExp {
  const regex = [...pattern]
    .map((char) => {
      if (char === '*') {
        return '.*'
      }
      if (char === '?') {
        return '.'
      }
      return escapeRegexCharacter(char)
    })
    .join('')
  return new RegExp(`^${regex}$`)
}

/**
 * Escapes a literal character for safe inclusion in a regular expression.
 *
 * @param char - Character to escape.
 * @returns Regex-safe literal character text.
 */
function escapeRegexCharacter(char: string): string {
  return char.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&')
}

/**
 * Removes duplicate strings while preserving encounter order.
 *
 * @param values - String values to de-duplicate.
 * @returns Unique strings in encounter order.
 */
function uniqueStrings(values: string[]): string[] {
  return [...new Set(values)]
}

/**
 * Removes duplicate numbers while preserving one copy of each value.
 *
 * @param values - Numeric values to de-duplicate.
 * @returns Unique numbers.
 */
function uniqueNumbers(values: number[]): number[] {
  return [...new Set(values)]
}

/**
 * Selects policy values to use for matching examples.
 *
 * @param conditionKey - Extracted condition-key policy values.
 * @param options - Scenario generation options.
 * @returns Either every policy value or one representative policy value.
 */
function policyValuesForScenarioGeneration(
  conditionKey: ExtractedConditionKey,
  options?: Pick<ScenarioGenerationOptions, 'showExamplesForAllPolicyValues'>
): string[] {
  if (options?.showExamplesForAllPolicyValues) {
    return conditionKey.values
  }
  return conditionKey.values.slice(0, 1)
}

/**
 * Generates present/missing values for the Null condition operator.
 *
 * @param conditionKey - Extracted condition-key policy values.
 * @param metadata - Scenario metadata used to choose a present value shape and missing-key availability.
 * @returns Scenario values that exercise allowed present and missing states.
 */
function nullOperatorValues(
  conditionKey: ExtractedConditionKey,
  metadata: ConditionKeyScenarioMetadata
): ScenarioValue[] {
  const wantsMissing = conditionKey.values.some((value) => value.toLowerCase() === 'true')
  const presentValue = nullOperatorPresentValue(conditionKey, metadata)
  if (!metadata.includeMissing) {
    return [presentValue]
  }

  const missingValue = { cellValue: null, contextValue: undefined }
  return wantsMissing ? [missingValue, presentValue] : [presentValue, missingValue]
}

/**
 * Generates numeric request values that exercise a numeric operator.
 *
 * @param policyNumber - Numeric policy value.
 * @param operator - Lowercase base condition operator.
 * @param matching - Whether to produce a value intended to match the operator.
 * @returns Numeric scenario value.
 */
function numericValueForOperator(
  policyNumber: number,
  operator: string,
  matching: boolean
): ScenarioValue {
  const base = Number.isNaN(policyNumber) ? 1 : policyNumber
  let value = base
  if (operator.includes('greater')) {
    value = matching ? base + 1 : base - 1
  } else if (operator.includes('less')) {
    value = matching ? base - 1 : base + 1
  } else if (operator.includes('notequals')) {
    value = matching ? base + 1 : base
  } else {
    value = matching ? base : base + 1
  }
  return { cellValue: value, contextValue: String(value) }
}

/**
 * Checks whether a numeric operator should use boundary scenario generation.
 *
 * @param baseOperator - Base condition operator without set prefix or IfExists suffix.
 * @returns True for less-than and greater-than numeric comparison operators.
 */
function isNumericComparisonOperator(baseOperator: string): boolean {
  const operator = baseOperator.toLowerCase()
  return operator.includes('lessthan') || operator.includes('greaterthan')
}

/**
 * Generates same, one-above, and one-below numeric scenarios for comparison operators.
 *
 * @param conditionKey - Extracted condition-key policy values.
 * @returns Numeric boundary scenario values.
 */
function numericComparisonValues(
  conditionKey: ExtractedConditionKey,
  options?: Pick<ScenarioGenerationOptions, 'showExamplesForAllPolicyValues'>
): ScenarioValue[] {
  const values = policyValuesForScenarioGeneration(conditionKey, options).flatMap((policyValue) => {
    const base = Number(policyValue)
    const policyNumber = Number.isNaN(base) ? 1 : base
    return [policyNumber - 1, policyNumber, policyNumber + 1]
  })
  return uniqueNumbers(values)
    .sort((left, right) => left - right)
    .map((value) => ({
      cellValue: value,
      contextValue: String(value)
    }))
}

/**
 * Generates date request values that exercise a date operator.
 *
 * @param policyValue - Date policy value.
 * @param operator - Lowercase base condition operator.
 * @param matching - Whether to produce a value intended to match the operator.
 * @returns Date scenario value.
 */
function dateValueForOperator(
  policyValue: string,
  operator: string,
  matching: boolean
): ScenarioValue {
  const base = Date.parse(policyValue)
  const baseDate = Number.isNaN(base) ? Date.parse('2024-01-01T00:00:00Z') : base
  let value = baseDate
  if (operator.includes('greater')) {
    value = matching ? baseDate + 86_400_000 : baseDate - 86_400_000
  } else if (operator.includes('less')) {
    value = matching ? baseDate - 86_400_000 : baseDate + 86_400_000
  } else if (operator.includes('notequals')) {
    value = matching ? baseDate + 86_400_000 : baseDate
  } else {
    value = matching ? baseDate : baseDate + 86_400_000
  }
  const date = new Date(value).toISOString()
  return { cellValue: date, contextValue: date }
}

/**
 * Generates IP request values that exercise IP address operators.
 *
 * @param operator - Lowercase base condition operator.
 * @param matching - Whether to produce a value intended to match the operator.
 * @returns IP address sample value.
 */
function sampleIpForOperator(operator: string, matching: boolean): string {
  const inRange = '203.0.113.10'
  const outOfRange = '198.51.100.10'
  if (operator.includes('not')) {
    return matching ? outOfRange : inRange
  }
  return matching ? inRange : outOfRange
}

/**
 * De-duplicates scenario values by cell/context representation.
 *
 * @param values - Candidate values to de-duplicate.
 * @returns Unique scenario values in encounter order.
 */
function uniqueScenarioValues(values: ScenarioValue[]): ScenarioValue[] {
  const seen = new Set<string>()
  const unique: ScenarioValue[] = []
  for (const value of values) {
    const key = JSON.stringify(value)
    if (!seen.has(key)) {
      seen.add(key)
      unique.push(value)
    }
  }
  return unique
}

/**
 * Builds the Cartesian product of all condition-key scenario values.
 *
 * @param valueSets - Values for each condition key.
 * @returns Generated scenarios.
 */
function cartesianScenarios(
  valueSets: Array<{ key: string; values: ScenarioValue[] }>
): GeneratedScenario[] {
  if (valueSets.length === 0) {
    return [{ scenarioId: 'row-1', cells: {}, context: {} }]
  }

  let rows: Array<{
    cells: Record<string, TruthTableCellValue>
    context: Record<string, string | string[]>
  }> = [{ cells: {}, context: {} }]

  for (const valueSet of valueSets) {
    const nextRows: typeof rows = []
    for (const row of rows) {
      for (const value of valueSet.values) {
        nextRows.push({
          cells: { ...row.cells, [valueSet.key]: value.cellValue },
          context:
            value.contextValue === undefined
              ? { ...row.context }
              : { ...row.context, [valueSet.key]: value.contextValue }
        })
      }
    }
    rows = filterCompatibleContextKeyRows(deduplicateRows(nextRows))
  }

  return rows.map((row, index) => ({
    scenarioId: `row-${index + 1}`,
    ...row
  }))
}

/**
 * De-duplicates rows with identical request context.
 *
 * @param rows - Generated rows to de-duplicate.
 * @returns De-duplicated rows in encounter order.
 */
function deduplicateRows(
  rows: Array<{
    cells: Record<string, TruthTableCellValue>
    context: Record<string, string | string[]>
  }>
): Array<{
  cells: Record<string, TruthTableCellValue>
  context: Record<string, string | string[]>
}> {
  const seen = new Set<string>()
  const unique: typeof rows = []
  for (const row of rows) {
    const key = JSON.stringify(row.context)
    if (!seen.has(key)) {
      seen.add(key)
      unique.push(row)
    }
  }
  return unique
}
