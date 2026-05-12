import { isAnyCellValue } from './simplify.js'
import {
  type GenerateTruthTablesResult,
  type PolicyTruthTable,
  type TruthTableCellValue,
  type TruthTableDiagnostic
} from './types.js'

/**
 * Renders a truth-table generation result as Markdown.
 *
 * @param result - Truth-table generation result to render.
 * @returns Markdown representation of the result.
 */
export function renderTruthTablesMarkdown(result: GenerateTruthTablesResult): string {
  if (result.resultType !== 'success') {
    return renderDiagnosticsMarkdown(
      result.diagnostics,
      `# ${titleForResultType(result.resultType)}`
    )
  }

  const sections = result.tables.map(renderTableMarkdown)
  if (result.diagnostics.length > 0) {
    sections.push(renderDiagnosticsMarkdown(result.diagnostics, '## Diagnostics'))
  }
  return sections.join('\n\n')
}

/**
 * Renders one policy truth table as Markdown.
 *
 * @param table - Policy truth table to render.
 * @returns Markdown table text.
 */
function renderTableMarkdown(table: PolicyTruthTable): string {
  const headers = table.columns.map((column) => column.label)
  const bodyRows = table.rows.map((row) =>
    table.columns.map((column) => cellToMarkdown(row.cells[column.key]))
  )
  const widths = columnWidths([headers, ...bodyRows])
  const headerRow = markdownRow(headers, widths)
  const separatorRow = markdownRow(
    widths.map((width) => '-'.repeat(width)),
    widths
  )
  const renderedBodyRows = bodyRows.map((row) => markdownRow(row, widths))

  return [
    `## ${escapeMarkdownText(table.title)}`,
    '',
    `Action tested: \`${escapeMarkdownText(table.testedAction)}\``,
    '',
    headerRow,
    separatorRow,
    ...renderedBodyRows
  ].join('\n')
}

/**
 * Renders diagnostics as a Markdown list.
 *
 * @param diagnostics - Diagnostics to render.
 * @param heading - Markdown heading to use before the diagnostic list.
 * @returns Markdown diagnostic section.
 */
function renderDiagnosticsMarkdown(diagnostics: TruthTableDiagnostic[], heading: string): string {
  if (diagnostics.length === 0) {
    return `${heading}\n\nNo diagnostics.`
  }
  return [
    heading,
    '',
    ...diagnostics.map(
      (diagnostic) =>
        `- **${diagnostic.severity}** \`${diagnostic.code}\`: ${escapeMarkdownText(diagnostic.message)}`
    )
  ].join('\n')
}

/**
 * Builds a Markdown table row.
 *
 * @param cells - Cell values to include in the row.
 * @returns Markdown table row.
 */
function markdownRow(cells: TruthTableCellValue[], widths: number[]): string {
  return `| ${cells.map((cell, index) => cellToMarkdown(cell).padEnd(widths[index] ?? 0, ' ')).join(' | ')} |`
}

/**
 * Calculates Markdown column widths from rendered cell values.
 *
 * @param rows - Rows to use when calculating column widths.
 * @returns Maximum rendered width for each column.
 */
function columnWidths(rows: TruthTableCellValue[][]): number[] {
  const widths: number[] = []
  for (const row of rows) {
    row.forEach((cell, index) => {
      widths[index] = Math.max(widths[index] ?? 0, cellToMarkdown(cell).length)
    })
  }
  return widths
}

/**
 * Converts a cell value into escaped Markdown table text.
 *
 * @param value - Cell value to render.
 * @returns Markdown-safe cell text.
 */
function cellToMarkdown(value: TruthTableCellValue | undefined): string {
  if (value === null || value === undefined) {
    return 'None'
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => escapeMarkdownText(String(item))).join(', ')}]`
  }
  if (isAnyCellValue(value)) {
    return value.label
  }
  return escapeMarkdownText(String(value))
}

/**
 * Escapes text for use in Markdown table cells and headings.
 *
 * @param value - Raw value to escape.
 * @returns Markdown-safe text.
 */
function escapeMarkdownText(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ')
}

/**
 * Converts result discriminants into Markdown headings.
 *
 * @param resultType - Result discriminant to label.
 * @returns Human-readable heading text.
 */
function titleForResultType(resultType: GenerateTruthTablesResult['resultType']): string {
  return resultType
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, (char) => char.toUpperCase())
    .trim()
}
