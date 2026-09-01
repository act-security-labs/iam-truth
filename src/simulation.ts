import {
  runSimulation,
  type RunSimulationResults,
  type Simulation
} from '@actsecurity/iam-simulate'
import { policyHasAllowStatement } from './effectMode.js'
import { type BaselineRequest } from './requestDefaults.js'
import { type GeneratedScenario } from './scenarios.js'
import {
  type JsonPolicyDocument,
  type TruthTableDiagnostic,
  type TruthTableMatchedStatement,
  type TruthTablePolicyEffectMode,
  type TruthTablePolicyType,
  type TruthTableRowResult
} from './types.js'

const GENERATED_IDENTITY_ALLOW_ALL = {
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }]
}

const GENERATED_SCP_FULL_ACCESS = {
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }]
}

/** Result of simulating one generated scenario. */
export type SimulateScenarioResult =
  | { resultType: 'success'; rowResult: TruthTableRowResult; diagnostics: TruthTableDiagnostic[] }
  | { resultType: 'error'; diagnostics: TruthTableDiagnostic[] }

/**
 * Simulates a generated scenario and maps the simulator result into an iam-truth row result.
 *
 * @param policyType - Target policy type.
 * @param policyDocument - Target policy document.
 * @param effectMode - Effect mode of the target policy.
 * @param baselineRequest - Baseline action/resource/principal values for simulation.
 * @param scenario - Generated condition context scenario.
 * @returns Row result or diagnostics when simulation fails.
 */
export async function simulateScenario(
  policyType: TruthTablePolicyType,
  policyDocument: JsonPolicyDocument,
  effectMode: TruthTablePolicyEffectMode,
  baselineRequest: BaselineRequest,
  scenario: GeneratedScenario
): Promise<SimulateScenarioResult> {
  const simulation = buildSimulation(policyType, policyDocument, baselineRequest, scenario)
  const result = await runSimulation(simulation, {})
  if (result.resultType === 'error') {
    return {
      resultType: 'error',
      diagnostics: [
        {
          severity: 'error',
          code: 'SIMULATION_ERROR',
          message: `Simulation failed: ${result.errors.message}`
        }
      ]
    }
  }

  return {
    resultType: 'success',
    rowResult: mapSimulationResult(result, effectMode, policyType),
    diagnostics: ignoredContextDiagnostics(result)
  }
}

/**
 * Builds the public iam-simulate input needed to evaluate one SCP scenario.
 *
 * @param policyDocument - Target SCP policy document.
 * @param baselineRequest - Baseline action/resource/principal values.
 * @param scenario - Generated context scenario.
 * @returns Public iam-simulate Simulation input.
 */
export function buildScpSimulation(
  policyDocument: JsonPolicyDocument,
  baselineRequest: BaselineRequest,
  scenario: GeneratedScenario
): Simulation {
  const scpPolicies = policyHasAllowStatement(policyDocument)
    ? [{ name: 'TargetPolicy', policy: policyDocument }]
    : [
        { name: 'GeneratedFullAWSAccess', policy: GENERATED_SCP_FULL_ACCESS },
        { name: 'TargetPolicy', policy: policyDocument }
      ]

  return {
    request: {
      principal: baselineRequest.principal,
      action: baselineRequest.action,
      resource: {
        resource: baselineRequest.resource,
        accountId: '111111111111'
      },
      contextVariables: scenario.context
    },
    identityPolicies: [{ name: 'GeneratedIdentityAllowAll', policy: GENERATED_IDENTITY_ALLOW_ALL }],
    serviceControlPolicies: [{ orgIdentifier: 'ou-iam-truth', policies: scpPolicies }],
    resourceControlPolicies: []
  }
}

/**
 * Builds the public iam-simulate input needed to evaluate one RCP scenario.
 *
 * @param policyDocument - Target RCP policy document.
 * @param baselineRequest - Baseline action/resource/principal values.
 * @param scenario - Generated context scenario.
 * @returns Public iam-simulate Simulation input.
 */
export function buildRcpSimulation(
  policyDocument: JsonPolicyDocument,
  baselineRequest: BaselineRequest,
  scenario: GeneratedScenario
): Simulation {
  return {
    request: {
      principal: baselineRequest.principal,
      action: baselineRequest.action,
      resource: {
        resource: baselineRequest.resource,
        accountId: '111111111111'
      },
      contextVariables: scenario.context
    },
    identityPolicies: [{ name: 'GeneratedIdentityAllowAll', policy: GENERATED_IDENTITY_ALLOW_ALL }],
    serviceControlPolicies: [],
    resourceControlPolicies: [
      {
        orgIdentifier: 'ou-iam-truth',
        policies: [{ name: 'TargetPolicy', policy: policyDocument }]
      }
    ]
  }
}

/**
 * Builds the public iam-simulate input for a policy type.
 *
 * @param policyType - Policy type being evaluated.
 * @param policyDocument - Target policy document.
 * @param baselineRequest - Baseline action/resource/principal values.
 * @param scenario - Generated context scenario.
 * @returns Public iam-simulate Simulation input.
 */
function buildSimulation(
  policyType: TruthTablePolicyType,
  policyDocument: JsonPolicyDocument,
  baselineRequest: BaselineRequest,
  scenario: GeneratedScenario
): Simulation {
  if (policyType === 'rcp') {
    return buildRcpSimulation(policyDocument, baselineRequest, scenario)
  }
  return buildScpSimulation(policyDocument, baselineRequest, scenario)
}

/**
 * Maps a successful iam-simulate result into a truth-table row result.
 *
 * @param result - Successful simulation result.
 * @param effectMode - Effect mode of the target policy.
 * @param policyType - Target policy type.
 * @returns User-facing row result.
 */
function mapSimulationResult(
  result: Exclude<RunSimulationResults, { resultType: 'error' }>,
  effectMode: TruthTablePolicyEffectMode,
  policyType: TruthTablePolicyType
): TruthTableRowResult {
  const overallResult = result.overallResult
  const matchedStatements = matchedDenyStatements(result, policyType)
  if (effectMode === 'denyOnly') {
    if (overallResult === 'ExplicitlyDenied') {
      return { resultType: 'explicitlyDenied', label: 'Denied', matchedStatements }
    }
    return { resultType: 'notDenied', label: 'Not Denied' }
  }

  if (overallResult === 'ExplicitlyDenied') {
    return { resultType: 'explicitlyDenied', label: 'Explicitly Denied', matchedStatements }
  }
  if (overallResult === 'Allowed') {
    return { resultType: 'allowed', label: 'Allowed' }
  }
  return { resultType: 'implicitlyDenied', label: 'Implicitly Denied' }
}

/**
 * Extracts target-policy matched deny statement references from a successful simulation result.
 *
 * @param result - Successful simulation result.
 * @param policyType - Target policy type.
 * @returns Statement references for matched target-policy deny statements.
 */
function matchedDenyStatements(
  result: Exclude<RunSimulationResults, { resultType: 'error' }>,
  policyType: TruthTablePolicyType
): TruthTableMatchedStatement[] {
  const analyses =
    result.resultType === 'single'
      ? [result.result.analysis]
      : result.results.map((r) => r.analysis)
  const statements = analyses.flatMap((analysis) => {
    const ouAnalysis =
      policyType === 'rcp'
        ? (analysis.rcpAnalysis?.ouAnalysis ?? [])
        : (analysis.scpAnalysis?.ouAnalysis ?? [])
    return ouAnalysis.flatMap((ou) =>
      ou.denyStatements
        .filter((statement) => statement.policyId === 'TargetPolicy')
        .map((statement) =>
          //iam-policy statement indexes are one-based; iam-truth exposes zero-based indexes.
          matchedStatementReference(statement.statement.index(), statement.statement.sid())
        )
    )
  })
  return uniqueMatchedStatements(statements)
}

/**
 * Builds a matched statement reference without serializing absent Sid values.
 *
 * @param index - One-based simulator statement index to convert to zero-based output.
 * @param sid - Optional statement Sid.
 * @returns Matched statement reference.
 */
function matchedStatementReference(
  index: number,
  sid: string | undefined
): TruthTableMatchedStatement {
  const zeroBasedIndex = index - 1
  return sid === undefined ? { index: zeroBasedIndex } : { index: zeroBasedIndex, sid }
}

/**
 * De-duplicates matched statement references by statement index.
 *
 * @param statements - Matched statement references to de-duplicate.
 * @returns Unique matched statements sorted by ascending index.
 */
function uniqueMatchedStatements(
  statements: TruthTableMatchedStatement[]
): TruthTableMatchedStatement[] {
  const byIndex = new Map<number, TruthTableMatchedStatement>()
  for (const statement of statements) {
    if (!byIndex.has(statement.index)) {
      byIndex.set(statement.index, statement)
    }
  }
  return [...byIndex.values()].sort((left, right) => left.index - right.index)
}

/**
 * Converts ignored simulator context keys into non-fatal diagnostics.
 *
 * @param result - Successful simulation result.
 * @returns Diagnostics for ignored context keys.
 */
function ignoredContextDiagnostics(
  result: Exclude<RunSimulationResults, { resultType: 'error' }>
): TruthTableDiagnostic[] {
  const ignored =
    result.resultType === 'single'
      ? (result.result.ignoredContextKeys ?? [])
      : result.results.flatMap((r) => r.ignoredContextKeys ?? [])
  return [...new Set(ignored)].map((key) => ({
    severity: 'warning' as const,
    code: 'IGNORED_CONTEXT_KEY' as const,
    message: `Context key ${key} was ignored by iam-simulate for the selected action/resource.`,
    conditionKey: key
  }))
}
