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
  if (scenarioResult.scenarios.length > maxRows) {
    return {
      resultType: 'tooManyScenarios',
      scenarioCount: scenarioResult.scenarios.length,
      maxScenarios: maxRows,
      diagnostics: [
        ...diagnostics,
        {
          severity: 'error',
          code: 'TOO_MANY_SCENARIOS',
          message: `Generated ${scenarioResult.scenarios.length} scenarios, exceeding the maximum of ${maxRows}.`
        }
      ]
    }
  }
  if (scenarioResult.scenarios.length > warnAtRows) {
    diagnostics.push({
      severity: 'warning',
      code: 'SCENARIO_COUNT_WARNING',
      message: `Generated ${scenarioResult.scenarios.length} scenarios, exceeding the warning threshold of ${warnAtRows}.`
    })
  }

  const rows: TruthTableRow[] = []
  for (const scenario of scenarioResult.scenarios) {
    const simulation = await simulateScenario(
      input.policyType,
      input.policy,
      effectMode,
      baselineRequest.request,
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
      rowId: scenario.scenarioId,
      cells: { ...scenario.cells, result: simulation.rowResult.label },
      context: scenario.context,
      result: simulation.rowResult
    })
  }

  let table: PolicyTruthTable = {
    tableId: 'policy',
    title: 'Policy Truth Table',
    policyType: input.policyType,
    effectMode,
    testedAction: baselineRequest.request.action,
    columns: columnsForScenarioMetadata(scenarioResult.metadata),
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
 * @returns Table columns including a trailing result column.
 */
function columnsForScenarioMetadata(
  metadata: Array<{ key: string; label: string; valueType: TruthTableColumn['valueType'] }>
): TruthTableColumn[] {
  return [
    ...metadata.map((item) => ({
      key: item.key,
      label: item.label,
      valueType: item.valueType
    })),
    { key: 'result', label: 'Result', valueType: 'result' as const }
  ]
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
