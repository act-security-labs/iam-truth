/** JSON value accepted by and returned from iam-truth APIs. */
export type JsonValue = string | number | boolean | null | JsonObject | JsonValue[]

/** JSON object accepted by and returned from iam-truth APIs. */
export interface JsonObject {
  [key: string]: JsonValue
}

/** A parsed IAM policy JSON document. */
export type JsonPolicyDocument = JsonObject

/** Policy types supported by iam-truth. */
export type TruthTablePolicyType = 'scp' | 'rcp'

/** Optional baseline request values used when simulating generated scenarios. */
export interface TruthTableRequestOverrides {
  /** IAM action to simulate for each generated scenario. */
  action?: string

  /** IAM resource strings to simulate for each generated scenario. Defaults to ['*']. */
  resources?: string[]

  /** Principal ARN to simulate for each generated scenario. */
  principal?: string
}

/** Input for generating truth tables from a single policy document. */
export interface GenerateTruthTablesInput {
  /** Parsed IAM policy JSON document. */
  policy: JsonPolicyDocument

  /** Policy type for the provided document. */
  policyType: TruthTablePolicyType

  /** Optional baseline request overrides for simulation. */
  request?: TruthTableRequestOverrides

  /** Optional generation controls. */
  options?: TruthTableGenerationOptions
}

/** Options controlling truth-table scenario generation. */
export interface TruthTableGenerationOptions {
  /** Maximum output rows to evaluate before returning a fatal too-many-rows result. Defaults to 1000. */
  maxRows?: number

  /** Output row count that should produce a warning diagnostic while still evaluating. Defaults to 25. */
  warnAtRows?: number

  /** Optional condition-key allow list for scenario generation. */
  targetConditionKeys?: string[]

  /** Whether to generate matching examples for every policy value. Defaults to false. */
  showExamplesForAllPolicyValues?: boolean

  /** Whether to simplify redundant truth-table rows into summary rows. Defaults to false. */
  simplifyTables?: boolean
}

/** Result of generating truth tables from a single policy document. */
export type GenerateTruthTablesResult =
  | GenerateTruthTablesSuccess
  | InvalidPolicyTruthTablesResult
  | UnsupportedPolicyTypeTruthTablesResult
  | UnsupportedConditionKeysTruthTablesResult
  | TooManyRowsTruthTablesResult
  | RequestDefaultUnsupportedTruthTablesResult
  | SimulationUnsupportedTruthTablesResult

/** Successful truth-table generation result. */
export interface GenerateTruthTablesSuccess {
  /** Discriminant for successful generation. */
  resultType: 'success'

  /** Truth tables generated for the policy. */
  tables: PolicyTruthTable[]

  /** Non-fatal diagnostics emitted while generating the tables. */
  diagnostics: TruthTableDiagnostic[]
}

/** Result returned when the input policy is invalid for the requested policy type. */
export interface InvalidPolicyTruthTablesResult {
  /** Discriminant for invalid policy input. */
  resultType: 'invalidPolicy'

  /** Validation diagnostics explaining why the policy is invalid. */
  diagnostics: TruthTableDiagnostic[]
}

/** Result returned when the policy type is not supported. */
export interface UnsupportedPolicyTypeTruthTablesResult {
  /** Discriminant for unsupported policy type input. */
  resultType: 'unsupportedPolicyType'

  /** Diagnostics explaining the unsupported policy type. */
  diagnostics: TruthTableDiagnostic[]
}

/** Result returned when condition keys cannot be meaningfully converted into scenarios. */
export interface UnsupportedConditionKeysTruthTablesResult {
  /** Discriminant for unsupported condition-key scenarios. */
  resultType: 'unsupportedConditionKeys'

  /** Diagnostics explaining which condition keys are unsupported. */
  diagnostics: TruthTableDiagnostic[]
}

/** Result returned when output row generation exceeds the configured maximum. */
export interface TooManyRowsTruthTablesResult {
  /** Discriminant for too many generated output rows. */
  resultType: 'tooManyRows'

  /** Number of condition-context scenarios that would have been generated. */
  scenarioCount: number

  /** Number of requested resources that would have been tested for each scenario. */
  resourceCount: number

  /** Number of output rows that would have been generated. */
  rowCount: number

  /** Maximum output row count allowed by options. */
  maxRows: number

  /** Diagnostics explaining the output row limit. */
  diagnostics: TruthTableDiagnostic[]
}

/** Result returned when baseline request defaults cannot be determined. */
export interface RequestDefaultUnsupportedTruthTablesResult {
  /** Discriminant for unsupported request default inference. */
  resultType: 'requestDefaultUnsupported'

  /** Diagnostics explaining which default could not be determined. */
  diagnostics: TruthTableDiagnostic[]
}

/** Result returned when generated scenarios cannot be simulated. */
export interface SimulationUnsupportedTruthTablesResult {
  /** Discriminant for unsupported simulation input or simulator errors. */
  resultType: 'simulationUnsupported'

  /** Diagnostics explaining why simulation failed. */
  diagnostics: TruthTableDiagnostic[]
}

/** A JSON truth table explaining one policy document. */
export interface PolicyTruthTable {
  /** Stable identifier for the table. */
  tableId: string

  /** Human-readable title for the table. */
  title: string

  /** Policy type used to generate the table. */
  policyType: TruthTablePolicyType

  /** Effect-mode derived from policy statements. */
  effectMode: TruthTablePolicyEffectMode

  /** IAM action used when generating and simulating table rows. */
  testedAction: string

  /** IAM resources used when simulating table rows, in requested evaluation order. */
  testedResources: string[]

  /** Table columns, including condition-key columns and the result column. */
  columns: TruthTableColumn[]

  /** Generated scenario rows. */
  rows: TruthTableRow[]

  /** Optional metadata describing table simplification when simplification was requested. */
  simplification?: TruthTableSimplificationSummary
}

/** A column in a policy truth table. */
export interface TruthTableColumn {
  /** Stable key for the column. */
  key: string

  /** Human-readable column label. */
  label: string

  /** Semantic value type displayed in the column. */
  valueType: TruthTableValueType
}

/** Supported truth-table cell value types. */
export type TruthTableValueType =
  'string' | 'boolean' | 'number' | 'ip' | 'arn' | 'date' | 'result' | 'unknown'

/** Summary cell representing any generated value for the column. */
export interface TruthTableAnyCellValue {
  /** Discriminant for an any-value summary cell. */
  cellType: 'any'

  /** Human-readable label for the any-value summary cell. */
  label: 'Any'
}

/** User-facing value displayed in a truth-table condition-key cell. */
export type TruthTableCellValue =
  string | boolean | number | null | string[] | boolean[] | number[] | TruthTableAnyCellValue

/** A generated row in a policy truth table. */
export type TruthTableRow = TruthTableScenarioRow | TruthTableSummaryRow

/** A concrete generated scenario row in a policy truth table. */
export interface TruthTableScenarioRow {
  /** Optional row discriminant. Omitted for concrete scenario rows. */
  rowType?: 'scenario'

  /** Stable row identifier. */
  rowId: string

  /** User-facing cell values keyed by column key. */
  cells: Record<string, TruthTableCellValue>

  /** Request context variables used for simulation. Missing keys are omitted. */
  context: Record<string, string | string[]>

  /** Row-level result mapped from simulator output and policy effect mode. */
  result: TruthTableRowResult

  /** Optional simulator explanation details retained as JSON. */
  explanation?: JsonValue
}

/** A summary row that represents multiple concrete generated scenario rows. */
export interface TruthTableSummaryRow {
  /** Row discriminant for simplified summary rows. */
  rowType: 'summary'

  /** Stable row identifier. */
  rowId: string

  /** User-facing cell values keyed by column key. */
  cells: Record<string, TruthTableCellValue>

  /** Row-level result shared by every covered concrete row. */
  result: TruthTableRowResult

  /** Number of concrete source rows represented by this summary row. */
  coveredRowCount: number

  /** Row IDs of concrete source rows represented by this summary row. */
  coveredRowIds: string[]
}

/** Metadata describing how a table was simplified. */
export interface TruthTableSimplificationSummary {
  /** Algorithm used to simplify the table. */
  strategy: 'greedyMaxCoverage'

  /** Number of concrete rows before simplification. */
  sourceRowCount: number

  /** Number of rows after simplification. */
  simplifiedRowCount: number
}

/** Target-policy statement matched while evaluating a truth-table row. */
export interface TruthTableMatchedStatement {
  /** Zero-based statement index in the input policy document. */
  index: number

  /** Optional statement Sid from the input policy document. */
  sid?: string
}

/** User-facing result for one generated scenario row. */
export type TruthTableRowResult =
  | { resultType: 'allowed'; label: 'Allowed' }
  | {
      resultType: 'explicitlyDenied'
      label: 'Explicitly Denied' | 'Denied'
      matchedStatements: TruthTableMatchedStatement[]
    }
  | { resultType: 'implicitlyDenied'; label: 'Implicitly Denied' }
  | { resultType: 'notDenied'; label: 'Not Denied' }

/** Effect composition of the input policy document. */
export type TruthTablePolicyEffectMode = 'denyOnly' | 'allowOnly' | 'allowAndDeny'

/** Machine-readable diagnostic emitted by iam-truth. */
export interface TruthTableDiagnostic {
  /** Diagnostic severity. */
  severity: 'info' | 'warning' | 'error'

  /** Stable diagnostic code. */
  code: TruthTableDiagnosticCode

  /** Human-readable diagnostic message. */
  message: string

  /** Optional policy path related to the diagnostic. */
  path?: string

  /** Optional condition key related to the diagnostic. */
  conditionKey?: string

  /** Optional policy type related to the diagnostic. */
  policyType?: TruthTablePolicyType | string
}

/** Stable diagnostic codes emitted by iam-truth. */
export type TruthTableDiagnosticCode =
  | 'INVALID_JSON_OBJECT'
  | 'INVALID_POLICY'
  | 'UNSUPPORTED_POLICY_TYPE'
  | 'UNSUPPORTED_CONDITION_KEY'
  | 'UNSUPPORTED_OPERATOR'
  | 'ROW_COUNT_WARNING'
  | 'TOO_MANY_ROWS'
  | 'REQUEST_DEFAULT_UNSUPPORTED'
  | 'SIMULATION_ERROR'
  | 'IGNORED_CONTEXT_KEY'

/** Parsed JSON policy file input returned by the CLI file argument. */
export interface PolicyFileInput {
  /** File path that was read. */
  path: string

  /** Parsed policy JSON document. */
  policy: JsonPolicyDocument
}
