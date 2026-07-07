import {
  loadPolicy,
  validateResourceControlPolicy,
  validateServiceControlPolicy,
  type ValidationError
} from '@cloud-copilot/iam-policy'
import { statementsApplicableToAction } from './actionFilter.js'
import { extractConditionKeysFromStatements } from './conditionKeys.js'
import { policyEffectMode } from './effectMode.js'
import { validateConditionOperators } from './operators.js'
import { resolveBaselineRequest } from './requestDefaults.js'
import { generateScenarios } from './scenarios.js'
import { simplifyTruthTable } from './simplify.js'
import { simulateScenario } from './simulation.js'
import {
  type GenerateTruthTablesInput,
  type GenerateTruthTablesResult,
  type PolicyTruthTable,
  type TruthTableColumn,
  type JsonPolicyDocument,
  type TruthTableDiagnostic,
  type TruthTablePolicyType,
  type TruthTableRow
} from './types.js'

const DEFAULT_WARN_AT_ROWS = 25
const DEFAULT_MAX_ROWS = 1000

/**
 * Generates JSON truth tables that explain one Organizations policy document across representative scenarios.
 *
 * @param input - Policy document, policy type, request overrides, and generation options.
 * @returns A typed JSON-serializable result containing truth tables or diagnostics.
 */
export async function generateTruthTables(
  input: GenerateTruthTablesInput
): Promise<GenerateTruthTablesResult> {
  if (!isSupportedPolicyType(input.policyType)) {
    return {
      resultType: 'unsupportedPolicyType',
      diagnostics: [
        {
          severity: 'error',
          code: 'UNSUPPORTED_POLICY_TYPE',
          message: `Unsupported policy type: ${input.policyType}`,
          policyType: input.policyType
        }
      ]
    }
  }

  const validationErrors = validatePolicyForType(input.policyType, input.policy)
  if (validationErrors.length > 0) {
    return {
      resultType: 'invalidPolicy',
      diagnostics: validationErrors.map((error) => ({
        severity: 'error',
        code: 'INVALID_POLICY',
        message: error.message,
        path: error.path,
        policyType: input.policyType
      }))
    }
  }

  const unsupportedOperatorDiagnostics = validateConditionOperators(input.policy)
  if (unsupportedOperatorDiagnostics.length > 0) {
    return { resultType: 'unsupportedConditionKeys', diagnostics: unsupportedOperatorDiagnostics }
  }

  const baselineRequest = await resolveBaselineRequest(input.policy, input.request)
  if (baselineRequest.resultType === 'unsupported') {
    return { resultType: 'requestDefaultUnsupported', diagnostics: baselineRequest.diagnostics }
  }

  const effectMode = policyEffectMode(input.policy)
  const applicableStatements = statementsApplicableToAction(
    loadPolicy(input.policy).statements(),
    baselineRequest.request.action
  )
  const conditionKeys = extractConditionKeysFromStatements(applicableStatements)
  const scenarioResult = await generateScenarios(conditionKeys, {
    targetConditionKeys: input.options?.targetConditionKeys,
    showExamplesForAllPolicyValues: input.options?.showExamplesForAllPolicyValues,
    requestContext: {
      policyType: input.policyType,
      requestModel: requestModelForPolicyType(input.policyType),
      action: baselineRequest.request.action,
      resource: baselineRequest.request.resource
    }
  })
  const diagnostics: TruthTableDiagnostic[] = [...scenarioResult.diagnostics]

  const maxRows = input.options?.maxRows ?? DEFAULT_MAX_ROWS
  const warnAtRows = input.options?.warnAtRows ?? DEFAULT_WARN_AT_ROWS
  const resources = baselineRequest.resources
  const rowCount = scenarioResult.scenarios.length * resources.length
  if (rowCount > maxRows) {
    return {
      resultType: 'tooManyRows',
      scenarioCount: scenarioResult.scenarios.length,
      resourceCount: resources.length,
      rowCount,
      maxRows,
      diagnostics: [
        ...diagnostics,
        {
          severity: 'error',
          code: 'TOO_MANY_ROWS',
          message: `Generated ${rowCount} rows from ${scenarioResult.scenarios.length} scenarios across ${resources.length} resources, exceeding the maximum of ${maxRows} rows.`
        }
      ]
    }
  }
  if (rowCount > warnAtRows) {
    diagnostics.push({
      severity: 'warning',
      code: 'ROW_COUNT_WARNING',
      message: `Generated ${rowCount} rows from ${scenarioResult.scenarios.length} scenarios across ${resources.length} resources, exceeding the warning threshold of ${warnAtRows} rows.`
    })
  }

  const rows: TruthTableRow[] = []
  const includeResourceColumn = resources.length > 1
  for (const scenario of scenarioResult.scenarios) {
    for (const resource of resources) {
      const resourceRequest = { ...baselineRequest.request, resource }
      const simulation = await simulateScenario(
        input.policyType,
        input.policy,
        effectMode,
        resourceRequest,
        scenario
      )
      if (simulation.resultType === 'error') {
        return {
          resultType: 'simulationUnsupported',
          diagnostics: [...diagnostics, ...simulation.diagnostics]
        }
      }
      diagnostics.push(...simulation.diagnostics)
      rows.push({
        rowId: `row-${rows.length + 1}`,
        cells: {
          ...scenario.cells,
          ...(includeResourceColumn ? { resource } : {}),
          result: simulation.rowResult.label
        },
        context: scenario.context,
        result: simulation.rowResult
      })
    }
  }

  let table: PolicyTruthTable = {
    tableId: 'policy',
    title: 'Policy Truth Table',
    policyType: input.policyType,
    effectMode,
    testedAction: baselineRequest.request.action,
    testedResources: resources,
    columns: columnsForScenarioMetadata(scenarioResult.metadata, includeResourceColumn),
    rows
  }

  if (input.options?.simplifyTables) {
    table = simplifyTruthTable(table)
  }

  return { resultType: 'success', tables: [table], diagnostics }
}

/**
 * Builds truth-table columns from condition-key metadata.
 *
 * @param metadata - Scenario metadata used to generate condition-key columns.
 * @param includeResourceColumn - Whether to include the tested resource column before the result.
 * @returns Table columns including an optional resource column and a trailing result column.
 */
function columnsForScenarioMetadata(
  metadata: Array<{ key: string; label: string; valueType: TruthTableColumn['valueType'] }>,
  includeResourceColumn: boolean
): TruthTableColumn[] {
  const columns: TruthTableColumn[] = metadata.map((item) => ({
    key: item.key,
    label: item.label,
    valueType: item.valueType
  }))
  if (includeResourceColumn) {
    columns.push({ key: 'resource', label: 'Resource', valueType: 'arn' })
  }
  columns.push({ key: 'result', label: 'Result', valueType: 'result' })
  return columns
}

/**
 * Checks whether a string is a supported truth-table policy type.
 *
 * @param policyType - Policy type to inspect.
 * @returns True when the policy type is supported.
 */
function isSupportedPolicyType(policyType: string): policyType is TruthTablePolicyType {
  return policyType === 'scp' || policyType === 'rcp'
}

/**
 * Validates a policy document according to the selected policy type.
 *
 * @param policyType - Policy type being evaluated.
 * @param policy - Parsed policy document to validate.
 * @returns Validation errors reported by iam-policy.
 */
function validatePolicyForType(
  policyType: TruthTablePolicyType,
  policy: JsonPolicyDocument
): ValidationError[] {
  if (policyType === 'rcp') {
    return validateResourceControlPolicy(policy)
  }
  return validateServiceControlPolicy(policy)
}

/**
 * Resolves the generated request model for a policy type.
 *
 * @param policyType - Policy type being evaluated.
 * @returns Generated request model used for condition-key metadata.
 */
function requestModelForPolicyType(
  policyType: TruthTablePolicyType
): 'generatedSignedScpRequest' | 'generatedSignedRcpRequest' {
  return policyType === 'rcp' ? 'generatedSignedRcpRequest' : 'generatedSignedScpRequest'
}
