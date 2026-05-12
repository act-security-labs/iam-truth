import {
  type PolicyTruthTable,
  type TruthTableAnyCellValue,
  type TruthTableCellValue,
  type TruthTableColumn,
  type TruthTableRow,
  type TruthTableRowResult,
  type TruthTableScenarioRow,
  type TruthTableSummaryRow
} from './types.js'

const ANY_CELL: TruthTableAnyCellValue = { cellType: 'any', label: 'Any' }
const MAX_EXHAUSTIVE_COLUMNS = 10
const MAX_FALLBACK_FIXED_COLUMNS = 3

interface SimplificationCandidate {
  fixedCells: Record<string, TruthTableCellValue>
  matchingRowIndexes: number[]
  fixedColumnCount: number
  stableKey: string
}

/**
 * Simplifies a truth table by replacing redundant concrete rows with summary rows.
 *
 * @param table - Fully simulated truth table containing concrete scenario rows.
 * @returns A new truth table with greedy max-coverage summary rows when possible.
 */
export function simplifyTruthTable(table: PolicyTruthTable): PolicyTruthTable {
  const conditionColumns = table.columns.filter((column) => column.key !== 'result')
  const sourceRows = table.rows.filter(isScenarioRow)
  const candidates = enumerateCandidates(sourceRows, conditionColumns)
  const covered = new Set<number>()
  const simplifiedRows: TruthTableRow[] = []

  while (covered.size < sourceRows.length) {
    const bestCandidate = bestUncoveredCandidate(candidates, covered)
    if (!bestCandidate || uncoveredIndexes(bestCandidate, covered).length < 2) {
      break
    }

    const newlyCovered = uncoveredIndexes(bestCandidate, covered)
    for (const rowIndex of newlyCovered) {
      covered.add(rowIndex)
    }

    simplifiedRows.push(summaryRow(bestCandidate, sourceRows, conditionColumns, newlyCovered))
  }

  for (const [index, row] of sourceRows.entries()) {
    if (!covered.has(index)) {
      simplifiedRows.push({ ...row })
    }
  }

  const rows = simplifiedRows.map((row, index) => ({ ...row, rowId: `row-${index + 1}` }))
  return {
    ...table,
    rows,
    simplification: {
      strategy: 'greedyMaxCoverage',
      sourceRowCount: sourceRows.length,
      simplifiedRowCount: rows.length
    }
  }
}

/**
 * Checks whether a truth-table cell is the any-value summary sentinel.
 *
 * @param value - Cell value to inspect.
 * @returns True when the value represents any generated value.
 */
export function isAnyCellValue(
  value: TruthTableCellValue | undefined
): value is TruthTableAnyCellValue {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    value.cellType === 'any' &&
    value.label === 'Any'
  )
}

/**
 * Returns a fresh any-value cell sentinel.
 *
 * @returns Any-value summary cell.
 */
export function anyCellValue(): TruthTableAnyCellValue {
  return { ...ANY_CELL }
}

/**
 * Determines whether a row is a concrete scenario row.
 *
 * @param row - Truth-table row to inspect.
 * @returns True when the row has concrete request context.
 */
function isScenarioRow(row: TruthTableRow): row is TruthTableScenarioRow {
  return row.rowType !== 'summary'
}

/**
 * Enumerates globally valid simplification candidates.
 *
 * @param rows - Concrete source rows.
 * @param conditionColumns - Columns that may be fixed or generalized.
 * @returns Valid candidates sorted deterministically.
 */
function enumerateCandidates(
  rows: TruthTableScenarioRow[],
  conditionColumns: TruthTableColumn[]
): SimplificationCandidate[] {
  const candidates = new Map<string, SimplificationCandidate>()

  for (const row of rows) {
    for (const columnSubset of columnSubsets(conditionColumns)) {
      const fixedCells = fixedCellsForRow(row, columnSubset)
      const matchingRowIndexes = rowsMatchingFixedCells(rows, fixedCells)
      if (matchingRowIndexes.length === 0) {
        continue
      }

      const firstResult = rows[matchingRowIndexes[0]].result
      const resultIdentity = resultIdentityKey(firstResult)
      if (
        !matchingRowIndexes.every(
          (index) => resultIdentityKey(rows[index].result) === resultIdentity
        )
      ) {
        continue
      }

      const stableKey = candidateStableKey(fixedCells, conditionColumns, resultIdentity)
      if (!candidates.has(stableKey)) {
        candidates.set(stableKey, {
          fixedCells,
          matchingRowIndexes,
          fixedColumnCount: columnSubset.length,
          stableKey
        })
      }
    }
  }

  return [...candidates.values()].sort(compareCandidatesDeterministically)
}

/**
 * Selects the best candidate for currently uncovered rows.
 *
 * @param candidates - Valid simplification candidates.
 * @param covered - Source row indexes already covered by emitted rows.
 * @returns The best candidate, or undefined when no candidate covers uncovered rows.
 */
function bestUncoveredCandidate(
  candidates: SimplificationCandidate[],
  covered: Set<number>
): SimplificationCandidate | undefined {
  let best: SimplificationCandidate | undefined
  let bestCoverage = 0

  for (const candidate of candidates) {
    const coverage = uncoveredIndexes(candidate, covered).length
    if (coverage === 0) {
      continue
    }
    if (
      !best ||
      coverage > bestCoverage ||
      (coverage === bestCoverage && candidatePrecedes(candidate, best))
    ) {
      best = candidate
      bestCoverage = coverage
    }
  }

  return best
}

/**
 * Compares candidates using stable readability tie-breakers.
 *
 * @param left - Left candidate.
 * @param right - Right candidate.
 * @returns Negative when left should sort before right.
 */
function compareCandidatesDeterministically(
  left: SimplificationCandidate,
  right: SimplificationCandidate
): number {
  if (left.fixedColumnCount !== right.fixedColumnCount) {
    return left.fixedColumnCount - right.fixedColumnCount
  }
  return left.stableKey.localeCompare(right.stableKey)
}

/**
 * Checks whether one candidate should win a tie against another.
 *
 * @param candidate - Candidate being considered.
 * @param best - Current best candidate.
 * @returns True when the candidate should replace the current best.
 */
function candidatePrecedes(
  candidate: SimplificationCandidate,
  best: SimplificationCandidate
): boolean {
  return compareCandidatesDeterministically(candidate, best) < 0
}

/**
 * Finds candidate row indexes that are not already covered.
 *
 * @param candidate - Candidate to inspect.
 * @param covered - Source row indexes already covered by emitted rows.
 * @returns Uncovered matching row indexes.
 */
function uncoveredIndexes(candidate: SimplificationCandidate, covered: Set<number>): number[] {
  return candidate.matchingRowIndexes.filter((index) => !covered.has(index))
}

/**
 * Builds a summary row from a selected candidate.
 *
 * @param candidate - Selected simplification candidate.
 * @param rows - Concrete source rows.
 * @param conditionColumns - Condition-key columns in table order.
 * @param coveredIndexes - Source row indexes newly represented by this summary.
 * @returns Summary row with any-value cells for generalized columns.
 */
function summaryRow(
  candidate: SimplificationCandidate,
  rows: TruthTableScenarioRow[],
  conditionColumns: TruthTableColumn[],
  coveredIndexes: number[]
): TruthTableSummaryRow {
  const cells: Record<string, TruthTableCellValue> = {}
  for (const column of conditionColumns) {
    cells[column.key] = Object.hasOwn(candidate.fixedCells, column.key)
      ? candidate.fixedCells[column.key]
      : anyCellValue()
  }
  const result = mergedResult(rows, coveredIndexes)
  cells.result = result.label

  return {
    rowType: 'summary',
    rowId: 'row-pending',
    cells,
    result,
    coveredRowCount: coveredIndexes.length,
    coveredRowIds: coveredIndexes.map((index) => rows[index].rowId)
  }
}

/**
 * Builds fixed cell values from a row for a subset of columns.
 *
 * @param row - Source row.
 * @param columns - Columns to fix.
 * @returns Fixed cell values keyed by column key.
 */
function fixedCellsForRow(
  row: TruthTableScenarioRow,
  columns: TruthTableColumn[]
): Record<string, TruthTableCellValue> {
  const fixedCells: Record<string, TruthTableCellValue> = {}
  for (const column of columns) {
    fixedCells[column.key] = row.cells[column.key]
  }
  return fixedCells
}

/**
 * Finds source rows matching fixed cell values.
 *
 * @param rows - Concrete source rows.
 * @param fixedCells - Fixed cell values to match.
 * @returns Indexes of matching rows.
 */
function rowsMatchingFixedCells(
  rows: TruthTableScenarioRow[],
  fixedCells: Record<string, TruthTableCellValue>
): number[] {
  const indexes: number[] = []
  for (const [index, row] of rows.entries()) {
    if (rowMatchesFixedCells(row, fixedCells)) {
      indexes.push(index)
    }
  }
  return indexes
}

/**
 * Checks whether one row matches all fixed cell values.
 *
 * @param row - Concrete source row.
 * @param fixedCells - Fixed cell values to match.
 * @returns True when all fixed cells match.
 */
function rowMatchesFixedCells(
  row: TruthTableScenarioRow,
  fixedCells: Record<string, TruthTableCellValue>
): boolean {
  return Object.entries(fixedCells).every(
    ([key, value]) => cellIdentityKey(row.cells[key]) === cellIdentityKey(value)
  )
}

/**
 * Produces every subset of the provided columns in deterministic order.
 *
 * @param columns - Columns to combine.
 * @returns Column subsets.
 */
function columnSubsets(columns: TruthTableColumn[]): TruthTableColumn[][] {
  if (columns.length <= MAX_EXHAUSTIVE_COLUMNS) {
    return exhaustiveColumnSubsets(columns)
  }

  const subsets: TruthTableColumn[][] = []
  for (let size = 0; size <= MAX_FALLBACK_FIXED_COLUMNS; size++) {
    subsets.push(...columnCombinations(columns, size))
  }
  return subsets
}

/**
 * Produces every subset of the provided columns.
 *
 * @param columns - Columns to combine.
 * @returns Every column subset.
 */
function exhaustiveColumnSubsets(columns: TruthTableColumn[]): TruthTableColumn[][] {
  const subsets: TruthTableColumn[][] = []
  const subsetCount = 2 ** columns.length
  for (let mask = 0; mask < subsetCount; mask++) {
    const subset: TruthTableColumn[] = []
    for (let index = 0; index < columns.length; index++) {
      if (Math.floor(mask / 2 ** index) % 2 === 1) {
        subset.push(columns[index])
      }
    }
    subsets.push(subset)
  }
  return subsets
}

/**
 * Produces combinations of a fixed size from the provided columns.
 *
 * @param columns - Columns to combine.
 * @param size - Number of columns in each combination.
 * @returns Column combinations of the requested size.
 */
function columnCombinations(columns: TruthTableColumn[], size: number): TruthTableColumn[][] {
  if (size === 0) {
    return [[]]
  }
  if (size > columns.length) {
    return []
  }

  const combinations: TruthTableColumn[][] = []
  const build = (startIndex: number, current: TruthTableColumn[]): void => {
    if (current.length === size) {
      combinations.push([...current])
      return
    }
    for (let index = startIndex; index < columns.length; index++) {
      current.push(columns[index])
      build(index + 1, current)
      current.pop()
    }
  }

  build(0, [])
  return combinations
}

/**
 * Builds a stable candidate key.
 *
 * @param fixedCells - Fixed candidate cells.
 * @param conditionColumns - Condition-key columns in table order.
 * @param resultIdentity - Result identity for the candidate.
 * @returns Stable candidate key.
 */
function candidateStableKey(
  fixedCells: Record<string, TruthTableCellValue>,
  conditionColumns: TruthTableColumn[],
  resultIdentity: string
): string {
  const parts = conditionColumns
    .filter((column) => fixedCells[column.key] !== undefined)
    .map((column) => `${column.key}=${cellIdentityKey(fixedCells[column.key])}`)
  return `${parts.join('|')}=>${resultIdentity}`
}

/**
 * Builds a stable identity key for a truth-table cell.
 *
 * @param value - Cell value to identify.
 * @returns Stable identity key.
 */
function cellIdentityKey(value: TruthTableCellValue | undefined): string {
  return JSON.stringify(value)
}

/**
 * Builds a stable user-facing identity key for a row result.
 *
 * @param result - Row result to identify.
 * @returns Stable result identity key.
 */
function resultIdentityKey(result: TruthTableRowResult): string {
  return JSON.stringify({ resultType: result.resultType, label: result.label })
}

/**
 * Builds a summary result for covered rows that share the same user-facing result.
 *
 * @param rows - Concrete source rows.
 * @param rowIndexes - Source row indexes represented by the summary.
 * @returns Row result for the summary row.
 */
function mergedResult(rows: TruthTableScenarioRow[], rowIndexes: number[]): TruthTableRowResult {
  const firstResult = rows[rowIndexes[0]].result
  if (firstResult.resultType === 'explicitlyDenied') {
    const matchedStatementIds = new Set<string>()
    for (const index of rowIndexes) {
      const result = rows[index].result
      if (result.resultType === 'explicitlyDenied') {
        for (const statementId of result.matchedStatementIds) {
          matchedStatementIds.add(statementId)
        }
      }
    }
    return {
      resultType: firstResult.resultType,
      label: firstResult.label,
      matchedStatementIds: [...matchedStatementIds].sort()
    }
  }
  return firstResult
}
