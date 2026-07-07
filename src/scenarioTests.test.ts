import { readdirSync, readFileSync, statSync } from 'fs'
import { dirname, join, relative } from 'path'
import { fileURLToPath } from 'url'
import { describe, expect, it } from 'vitest'
import { generateTruthTables } from './generateTruthTables.js'
import {
  type GenerateTruthTablesInput,
  type GenerateTruthTablesResult,
  type TruthTableCellValue,
  type TruthTableColumn,
  type TruthTableDiagnostic,
  type TruthTableDiagnosticCode,
  type TruthTablePolicyEffectMode,
  type TruthTableSimplificationSummary
} from './types.js'

interface ScenarioTestFile {
  description?: string
  cases: ScenarioTestCase[]
}

interface ScenarioTestCase {
  name: string
  skip?: boolean
  only?: boolean
  input: GenerateTruthTablesInput
  expected: ScenarioExpectation
}

type ScenarioExpectation =
  | {
      exactResult: GenerateTruthTablesResult
    }
  | {
      resultType: GenerateTruthTablesResult['resultType']
      diagnostics?: {
        includes?: ExpectedDiagnostic[]
        excludesCodes?: TruthTableDiagnosticCode[]
      }
      table?: {
        effectMode?: TruthTablePolicyEffectMode
        testedAction?: string
        testedResources?: string[]
        rowCount?: number
        columns?: TruthTableColumn[]
        columnKeys?: string[]
        includesColumnKeys?: string[]
        rowResults?: string[]
        includesRowResults?: string[]
        rows?: CompactExpectedRow[]
        rowsInclude?: ExpectedRowPartial[]
        simplification?: TruthTableSimplificationSummary
      }
    }

type CompactExpectedRowValue = TruthTableCellValue

type CompactExpectedRow = CompactExpectedRowValue[]

interface ExpectedDiagnostic {
  code: string
  severity?: 'info' | 'warning' | 'error'
  conditionKey?: string
  path?: string
}

interface ExpectedRowPartial {
  cells?: Record<string, TruthTableCellValue>
  result?: { resultType?: string; label?: string }
}

const testFolder = join(dirname(fileURLToPath(import.meta.url)), 'scenario-tests')
const testFiles = getJsonFiles(testFolder).sort()

/**
 * Recursively finds JSON scenario fixture files below a directory.
 *
 * @param directory - Directory to search for JSON fixture files.
 * @returns Absolute paths to JSON fixture files.
 */
function getJsonFiles(directory: string): string[] {
  const entries = readdirSync(directory)
  const files: string[] = []
  for (const entry of entries) {
    const entryPath = join(directory, entry)
    const entryStat = statSync(entryPath)
    if (entryStat.isDirectory()) {
      files.push(...getJsonFiles(entryPath))
    } else if (entry.endsWith('.json')) {
      files.push(entryPath)
    }
  }
  return files
}

describe('JSON-driven scenario tests', () => {
  for (const testFile of testFiles) {
    const filePath = testFile
    const relativeTestFile = relative(testFolder, testFile)
    const contents = readFileSync(filePath, 'utf8')
    const testDocument = JSON.parse(contents) as ScenarioTestFile

    describe(relativeTestFile, () => {
      for (const testCase of testDocument.cases) {
        const testFunc = testCase.only ? it.only : testCase.skip ? it.skip : it
        testFunc(testCase.name, async () => {
          //Given a JSON scenario fixture case
          const input = testCase.input

          //When truth tables are generated
          const result = await generateTruthTables(input)

          //Then the result should match the fixture expectations
          assertScenarioExpectation(
            result,
            testCase.expected,
            `${relativeTestFile}: ${testCase.name}`
          )
        })
      }
    })
  }
})

/**
 * Asserts that an actual generation result matches a scenario fixture expectation.
 *
 * @param result - Actual generation result returned by the public API.
 * @param expected - Expected fixture assertion data.
 * @param caseName - Human-readable fixture/case identifier for assertion messages.
 */
function assertScenarioExpectation(
  result: GenerateTruthTablesResult,
  expected: ScenarioExpectation,
  caseName: string
): void {
  if ('exactResult' in expected) {
    expect(result, `${caseName} exact result`).toEqual(expected.exactResult)
    return
  }

  expect(result.resultType, `${caseName} resultType`).toBe(expected.resultType)
  assertDiagnostics(result.diagnostics, expected.diagnostics, caseName)

  if (expected.table) {
    expect(result.resultType, `${caseName} table result type`).toBe('success')
    if (result.resultType !== 'success') {
      throw new Error(`${caseName} expected success result for table assertions`)
    }
    const table = result.tables[0]
    expect(table, `${caseName} first table`).toBeDefined()
    if (expected.table.effectMode) {
      expect(table.effectMode, `${caseName} effectMode`).toBe(expected.table.effectMode)
    }
    if (expected.table.testedAction) {
      expect(table.testedAction, `${caseName} testedAction`).toBe(expected.table.testedAction)
    }
    if (expected.table.testedResources) {
      expect(table.testedResources, `${caseName} testedResources`).toEqual(
        expected.table.testedResources
      )
    }
    if (expected.table.rowCount !== undefined) {
      expect(table.rows.length, `${caseName} rowCount`).toBe(expected.table.rowCount)
    }
    if (expected.table.columns) {
      expect(table.columns, `${caseName} columns`).toEqual(expected.table.columns)
    }
    if (expected.table.columnKeys) {
      expect(
        table.columns.map((column) => column.key),
        `${caseName} columnKeys`
      ).toEqual(expected.table.columnKeys)
    }
    if (expected.table.includesColumnKeys) {
      const actualColumnKeys = table.columns.map((column) => column.key)
      for (const columnKey of expected.table.includesColumnKeys) {
        expect(actualColumnKeys, `${caseName} includes column ${columnKey}`).toContain(columnKey)
      }
    }
    if (expected.table.rowResults) {
      expect(
        table.rows.map((row) => row.result.label),
        `${caseName} rowResults`
      ).toEqual(expected.table.rowResults)
    }
    if (expected.table.includesRowResults) {
      const actualRowResults = table.rows.map((row) => row.result.label)
      for (const rowResult of expected.table.includesRowResults) {
        expect(actualRowResults, `${caseName} includes row result ${rowResult}`).toContain(
          rowResult
        )
      }
    }
    if (expected.table.simplification) {
      expect(table.simplification, `${caseName} simplification`).toEqual(
        expected.table.simplification
      )
    }
    if (expected.table.rows) {
      expect(
        table.rows.map((row, index) => compactRow(table.columns, row, index)),
        `${caseName} compact rows`
      ).toEqual(expected.table.rows)
    }
    if (expected.table.rowsInclude) {
      for (const rowPartial of expected.table.rowsInclude) {
        expect(
          table.rows.some((row) => rowMatches(row, rowPartial)),
          `${caseName} includes row ${JSON.stringify(rowPartial)}`
        ).toBe(true)
      }
    }
  }
}

/**
 * Asserts diagnostic include/exclude expectations.
 *
 * @param diagnostics - Actual diagnostics emitted by the API.
 * @param expected - Optional diagnostic expectations from the fixture.
 * @param caseName - Human-readable fixture/case identifier for assertion messages.
 */
function assertDiagnostics(
  diagnostics: TruthTableDiagnostic[],
  expected: ScenarioExpectation['diagnostics'],
  caseName: string
): void {
  if (!expected) {
    return
  }
  for (const expectedDiagnostic of expected.includes ?? []) {
    expect(
      diagnostics.some((diagnostic) => diagnosticMatches(diagnostic, expectedDiagnostic)),
      `${caseName} includes diagnostic ${JSON.stringify(expectedDiagnostic)}`
    ).toBe(true)
  }
  for (const excludedCode of expected.excludesCodes ?? []) {
    expect(
      diagnostics.some((diagnostic) => diagnostic.code === excludedCode),
      `${caseName} excludes diagnostic code ${excludedCode}`
    ).toBe(false)
  }
}

/**
 * Converts a full truth-table row into a compact positional fixture row.
 *
 * @param columns - Table columns that define positional row values.
 * @param row - Actual truth-table row to convert.
 * @param index - Zero-based row index used to verify implied row id.
 * @returns Compact row values where the result column uses `result.resultType`.
 */
function compactRow(
  columns: TruthTableColumn[],
  row: {
    rowId: string
    cells: Record<string, TruthTableCellValue>
    result: { resultType: string }
  },
  index: number
): CompactExpectedRow {
  expect(row.rowId, `compact row ${index + 1} rowId`).toBe(`row-${index + 1}`)
  return columns.map((column) =>
    column.key === 'result' ? row.result.resultType : row.cells[column.key]
  )
}

/**
 * Checks whether an actual diagnostic matches a partial diagnostic expectation.
 *
 * @param diagnostic - Actual diagnostic emitted by the API.
 * @param expected - Partial diagnostic expectation from a fixture.
 * @returns True when all provided expected fields match.
 */
function diagnosticMatches(
  diagnostic: TruthTableDiagnostic,
  expected: ExpectedDiagnostic
): boolean {
  return (
    diagnostic.code === expected.code &&
    (expected.severity === undefined || diagnostic.severity === expected.severity) &&
    (expected.conditionKey === undefined || diagnostic.conditionKey === expected.conditionKey) &&
    (expected.path === undefined || diagnostic.path === expected.path)
  )
}

/**
 * Checks whether a truth-table row matches a partial row expectation.
 *
 * @param row - Actual truth-table row.
 * @param expected - Partial row expectation from a fixture.
 * @returns True when all expected cells and result fields match.
 */
function rowMatches(
  row: {
    cells: Record<string, TruthTableCellValue>
    result: { resultType: string; label: string }
  },
  expected: ExpectedRowPartial
): boolean {
  for (const [key, value] of Object.entries(expected.cells ?? {})) {
    if (JSON.stringify(row.cells[key]) !== JSON.stringify(value)) {
      return false
    }
  }
  if (expected.result?.resultType && row.result.resultType !== expected.result.resultType) {
    return false
  }
  if (expected.result?.label && row.result.label !== expected.result.label) {
    return false
  }
  return true
}
