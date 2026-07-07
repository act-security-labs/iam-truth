import { describe, expect, it } from 'vitest'
import { anyCellValue, simplifyTruthTable } from './simplify.js'
import {
  type PolicyTruthTable,
  type TruthTableCellValue,
  type TruthTableColumn,
  type TruthTableRowResult,
  type TruthTableScenarioRow
} from './types.js'

describe('simplifyTruthTable', () => {
  it('should summarize the dominant single-key result first', () => {
    //Given a table where one fixed value determines four denied rows
    const table = tableWithRows(
      ['aws:SecureTransport', 'tag', 'region'],
      [
        row(1, { 'aws:SecureTransport': false, tag: 'a', region: 'east' }, denied('DenyTLS')),
        row(2, { 'aws:SecureTransport': false, tag: 'a', region: 'west' }, denied('DenyTLS')),
        row(3, { 'aws:SecureTransport': false, tag: 'b', region: 'east' }, denied('DenyTLS')),
        row(4, { 'aws:SecureTransport': false, tag: 'b', region: 'west' }, denied('DenyTLS')),
        row(5, { 'aws:SecureTransport': true, tag: 'a', region: 'east' }, notDenied()),
        row(6, { 'aws:SecureTransport': true, tag: 'b', region: 'east' }, denied('DenyTag'))
      ]
    )

    //When the table is simplified
    const result = simplifyTruthTable(table)

    //Then the largest reduction should be emitted as the first summary row
    expect(result.rows[0]).toEqual({
      rowType: 'summary',
      rowId: 'row-1',
      cells: {
        'aws:SecureTransport': false,
        tag: anyCellValue(),
        region: anyCellValue(),
        result: 'Denied'
      },
      result: denied('DenyTLS'),
      coveredRowCount: 4,
      coveredRowIds: ['row-1', 'row-2', 'row-3', 'row-4']
    })
    expect(result.simplification).toEqual({
      strategy: 'greedyMaxCoverage',
      sourceRowCount: 6,
      simplifiedRowCount: 3
    })
  })

  it('should consider multi-key combinations when single-key candidates are invalid', () => {
    //Given rows where only a two-key pattern has a consistent result across multiple rows
    const table = tableWithRows(
      ['a', 'b', 'c'],
      [
        row(1, { a: 'x', b: 'y', c: '1' }, denied('DenyXY')),
        row(2, { a: 'x', b: 'y', c: '2' }, denied('DenyXY')),
        row(3, { a: 'x', b: 'z', c: '1' }, notDenied()),
        row(4, { a: 'w', b: 'y', c: '1' }, notDenied())
      ]
    )

    //When the table is simplified
    const result = simplifyTruthTable(table)

    //Then the two-key pattern should be summarized
    expect(result.rows[0]).toEqual({
      rowType: 'summary',
      rowId: 'row-1',
      cells: { a: 'x', b: 'y', c: anyCellValue(), result: 'Denied' },
      result: denied('DenyXY'),
      coveredRowCount: 2,
      coveredRowIds: ['row-1', 'row-2']
    })
  })

  it('should not summarize a candidate that has mixed results in the original table', () => {
    //Given two rows where the only broad candidate has mixed results
    const table = tableWithRows(
      ['a'],
      [row(1, { a: 'x' }, denied('DenyX')), row(2, { a: 'y' }, notDenied())]
    )

    //When the table is simplified
    const result = simplifyTruthTable(table)

    //Then no summary row should be emitted
    expect(result.rows).toEqual(table.rows)
    expect(result.simplification).toEqual({
      strategy: 'greedyMaxCoverage',
      sourceRowCount: 2,
      simplifiedRowCount: 2
    })
  })

  it('should not combine explicitly denied rows with implicitly denied rows', () => {
    //Given explicit and implicit deny rows that would otherwise share an all-any candidate
    const table = tableWithRows(
      ['a'],
      [row(1, { a: 'x' }, denied('DenyX')), row(2, { a: 'y' }, implicitlyDenied())]
    )

    //When the table is simplified
    const result = simplifyTruthTable(table)

    //Then the distinct result types should prevent summarization
    expect(result.rows).toEqual(table.rows)
  })

  it('should summarize all rows when every result is identical', () => {
    //Given every row has the same result
    const table = tableWithRows(
      ['a', 'b'],
      [
        row(1, { a: 'x', b: '1' }, notDenied()),
        row(2, { a: 'x', b: '2' }, notDenied()),
        row(3, { a: 'y', b: '1' }, notDenied())
      ]
    )

    //When the table is simplified
    const result = simplifyTruthTable(table)

    //Then one all-any summary row should represent the table
    expect(result.rows).toEqual([
      {
        rowType: 'summary',
        rowId: 'row-1',
        cells: { a: anyCellValue(), b: anyCellValue(), result: 'Not Denied' },
        result: notDenied(),
        coveredRowCount: 3,
        coveredRowIds: ['row-1', 'row-2', 'row-3']
      }
    ])
  })

  it('should collapse the resource column when results are identical across resources', () => {
    //Given rows where only the tested resource differs and the result is identical
    const table = tableWithRows(
      ['resource'],
      [
        row(1, { resource: 'arn:aws:s3:::example-bucket/first.txt' }, denied('DenyReads')),
        row(2, { resource: 'arn:aws:s3:::example-bucket/second.txt' }, denied('DenyReads'))
      ]
    )

    //When the table is simplified
    const result = simplifyTruthTable(table)

    //Then resource should collapse to Any like any other non-result column
    expect(result.rows).toEqual([
      {
        rowType: 'summary',
        rowId: 'row-1',
        cells: { resource: anyCellValue(), result: 'Denied' },
        result: denied('DenyReads'),
        coveredRowCount: 2,
        coveredRowIds: ['row-1', 'row-2']
      }
    ])
  })

  it('should not collapse the resource column when results differ across resources', () => {
    //Given rows where the tested resource changes the result
    const table = tableWithRows(
      ['resource'],
      [
        row(1, { resource: 'arn:aws:s3:::example-bucket/first.txt' }, denied('DenyFirst')),
        row(2, { resource: 'arn:aws:s3:::example-bucket/second.txt' }, notDenied())
      ]
    )

    //When the table is simplified
    const result = simplifyTruthTable(table)

    //Then resource values should stay concrete because an Any resource would mix results
    expect(result.rows).toEqual(table.rows)
    expect(result.simplification).toEqual({
      strategy: 'greedyMaxCoverage',
      sourceRowCount: 2,
      simplifiedRowCount: 2
    })
  })

  it('should support null and array cell values when finding summaries', () => {
    //Given rows with null and array-valued cells
    const table = tableWithRows(
      ['missingKey', 'tagKeys', 'other'],
      [
        row(1, { missingKey: null, tagKeys: ['team', 'dept'], other: '1' }, denied('DenyTags')),
        row(2, { missingKey: null, tagKeys: ['team', 'dept'], other: '2' }, denied('DenyTags')),
        row(3, { missingKey: 'present', tagKeys: ['team', 'dept'], other: '1' }, notDenied()),
        row(4, { missingKey: null, tagKeys: ['project'], other: '1' }, notDenied())
      ]
    )

    //When the table is simplified
    const result = simplifyTruthTable(table)

    //Then the summary should preserve fixed null and array values
    expect(result.rows[0]).toEqual({
      rowType: 'summary',
      rowId: 'row-1',
      cells: {
        missingKey: null,
        tagKeys: ['team', 'dept'],
        other: anyCellValue(),
        result: 'Denied'
      },
      result: denied('DenyTags'),
      coveredRowCount: 2,
      coveredRowIds: ['row-1', 'row-2']
    })
  })

  it('should use bounded subset enumeration for wide tables', () => {
    //Given a table with more columns than the exhaustive subset limit
    const conditionKeys = Array.from({ length: 11 }, (_, index) => `key${index + 1}`)
    const firstCells = Object.fromEntries(conditionKeys.map((key) => [key, 'a']))
    const secondCells = Object.fromEntries(conditionKeys.map((key) => [key, 'b']))
    const table = tableWithRows(conditionKeys, [
      row(1, firstCells, notDenied()),
      row(2, secondCells, notDenied())
    ])

    //When the table is simplified
    const result = simplifyTruthTable(table)

    //Then the all-any candidate should still be available through the fallback path
    expect(result.rows).toEqual([
      {
        rowType: 'summary',
        rowId: 'row-1',
        cells: {
          ...Object.fromEntries(conditionKeys.map((key) => [key, anyCellValue()])),
          result: 'Not Denied'
        },
        result: notDenied(),
        coveredRowCount: 2,
        coveredRowIds: ['row-1', 'row-2']
      }
    ])
  })

  it('should merge explicit denies with the same user-facing result and combine matched statements', () => {
    //Given rows with the same label but different matched deny statements
    const table = tableWithRows(
      ['a', 'b'],
      [
        row(1, { a: 'x', b: '1' }, denied('DenyOne', 0)),
        row(2, { a: 'x', b: '2' }, denied('DenyTwo', 1))
      ]
    )

    //When the table is simplified
    const result = simplifyTruthTable(table)

    //Then the summary should combine matched statement references for traceability
    expect(result.rows).toEqual([
      {
        rowType: 'summary',
        rowId: 'row-1',
        cells: { a: anyCellValue(), b: anyCellValue(), result: 'Denied' },
        result: {
          resultType: 'explicitlyDenied',
          label: 'Denied',
          matchedStatements: [
            { index: 0, sid: 'DenyOne' },
            { index: 1, sid: 'DenyTwo' }
          ]
        },
        coveredRowCount: 2,
        coveredRowIds: ['row-1', 'row-2']
      }
    ])
  })
})

/**
 * Creates a minimal policy truth table for simplification tests.
 *
 * @param conditionKeys - Condition column keys.
 * @param rows - Concrete scenario rows.
 * @returns Policy truth table.
 */
function tableWithRows(conditionKeys: string[], rows: TruthTableScenarioRow[]): PolicyTruthTable {
  const columns: TruthTableColumn[] = [
    ...conditionKeys.map((key) => ({
      key,
      label: key === 'resource' ? 'Resource' : key,
      valueType: key === 'resource' ? ('arn' as const) : ('string' as const)
    })),
    { key: 'result', label: 'Result', valueType: 'result' }
  ]
  return {
    tableId: 'policy',
    title: 'Policy Truth Table',
    policyType: 'scp',
    effectMode: 'denyOnly',
    testedAction: 's3:PutObject',
    testedResources: ['*'],
    untestedResources: [],
    columns,
    rows
  }
}

/**
 * Creates a concrete truth-table scenario row for simplification tests.
 *
 * @param index - One-based row index.
 * @param cells - Condition-key cells.
 * @param result - Row result.
 * @returns Concrete scenario row.
 */
function row(
  index: number,
  cells: Record<string, TruthTableCellValue>,
  result: TruthTableRowResult
): TruthTableScenarioRow {
  return {
    rowId: `row-${index}`,
    cells: { ...cells, result: result.label },
    context: {},
    result
  }
}

/**
 * Creates an explicitly denied row result for tests.
 *
 * @param sid - Matched statement Sid.
 * @param index - Zero-based matched statement index.
 * @returns Explicitly denied row result.
 */
function denied(sid: string, index = 0): TruthTableRowResult {
  return {
    resultType: 'explicitlyDenied',
    label: 'Denied',
    matchedStatements: [{ index, sid }]
  }
}

/**
 * Creates a not-denied row result for tests.
 *
 * @returns Not denied row result.
 */
function notDenied(): TruthTableRowResult {
  return { resultType: 'notDenied', label: 'Not Denied' }
}

/**
 * Creates an implicitly denied row result for tests.
 *
 * @returns Implicitly denied row result.
 */
function implicitlyDenied(): TruthTableRowResult {
  return { resultType: 'implicitlyDenied', label: 'Implicitly Denied' }
}
