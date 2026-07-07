import { describe, expect, it } from 'vitest'
import { renderTruthTablesMarkdown } from './markdown.js'
import { type GenerateTruthTablesResult } from './types.js'

describe('renderTruthTablesMarkdown', () => {
  it('should render successful truth tables as markdown tables', () => {
    //Given a successful truth-table result
    const result: GenerateTruthTablesResult = {
      resultType: 'success',
      tables: [
        {
          tableId: 'policy',
          title: 'Policy Truth Table',
          policyType: 'scp',
          effectMode: 'denyOnly',
          testedAction: 's3:PutObject',
          testedResources: ['*'],
          columns: [
            { key: 'aws:ResourceOrgID', label: 'Organization ID', valueType: 'string' },
            { key: 'aws:ViaAWSService', label: 'Is Via Service?', valueType: 'boolean' },
            { key: 'result', label: 'Result', valueType: 'result' }
          ],
          rows: [
            {
              rowId: 'row-1',
              cells: {
                'aws:ResourceOrgID': 'o-h2owf1zaat',
                'aws:ViaAWSService': true,
                result: 'Not Denied'
              },
              context: {
                'aws:ResourceOrgID': 'o-h2owf1zaat',
                'aws:ViaAWSService': 'true'
              },
              result: { resultType: 'notDenied', label: 'Not Denied' }
            },
            {
              rowId: 'row-2',
              cells: {
                'aws:ResourceOrgID': null,
                'aws:ViaAWSService': false,
                result: 'Denied'
              },
              context: {
                'aws:ViaAWSService': 'false'
              },
              result: {
                resultType: 'explicitlyDenied',
                label: 'Denied',
                matchedStatements: [{ index: 0, sid: 'Deny' }]
              }
            }
          ]
        }
      ],
      diagnostics: []
    }

    //When the result is rendered as Markdown
    const markdown = renderTruthTablesMarkdown(result)

    //Then it should include a formatted Markdown table
    expect(markdown).toBe(`## Policy Truth Table

Action tested: \`s3:PutObject\`

| Organization ID | Is Via Service? | Result     |
| --------------- | --------------- | ---------- |
| o-h2owf1zaat    | true            | Not Denied |
| None            | false           | Denied     |`)
  })

  it('should render resource columns for multi-resource tables', () => {
    //Given a successful result with a resource column
    const result: GenerateTruthTablesResult = {
      resultType: 'success',
      tables: [
        {
          tableId: 'policy',
          title: 'Resource Test',
          policyType: 'scp',
          effectMode: 'denyOnly',
          testedAction: 's3:GetObject',
          testedResources: [
            'arn:aws:s3:::example-bucket/first.txt',
            'arn:aws:s3:::example-bucket/second.txt'
          ],
          columns: [
            { key: 'resource', label: 'Resource', valueType: 'arn' },
            { key: 'result', label: 'Result', valueType: 'result' }
          ],
          rows: [
            {
              rowId: 'row-1',
              cells: {
                resource: 'arn:aws:s3:::example-bucket/first.txt',
                result: 'Denied'
              },
              context: {},
              result: {
                resultType: 'explicitlyDenied',
                label: 'Denied',
                matchedStatements: [{ index: 0, sid: 'Deny' }]
              }
            }
          ]
        }
      ],
      diagnostics: []
    }

    //When the result is rendered as Markdown
    const markdown = renderTruthTablesMarkdown(result)

    //Then it should include the tested resource cell
    expect(markdown).toContain('| arn:aws:s3:::example-bucket/first.txt | Denied |')
  })

  it('should escape markdown table cell pipes', () => {
    //Given a successful result with a pipe in a cell value
    const result: GenerateTruthTablesResult = {
      resultType: 'success',
      tables: [
        {
          tableId: 'policy',
          title: 'Pipe Test',
          policyType: 'scp',
          effectMode: 'denyOnly',
          testedAction: 's3:PutObject',
          testedResources: ['*'],
          columns: [
            { key: 'aws:UserAgent', label: 'User Agent', valueType: 'string' },
            { key: 'result', label: 'Result', valueType: 'result' }
          ],
          rows: [
            {
              rowId: 'row-1',
              cells: { 'aws:UserAgent': 'a|b', result: 'Not Denied' },
              context: { 'aws:UserAgent': 'a|b' },
              result: { resultType: 'notDenied', label: 'Not Denied' }
            }
          ]
        }
      ],
      diagnostics: []
    }

    //When the result is rendered as Markdown
    const markdown = renderTruthTablesMarkdown(result)

    //Then it should escape the pipe in the cell
    expect(markdown).toContain('| a\\\\|b      | Not Denied |')
  })

  it('should render array cells as markdown lists', () => {
    //Given a successful result with an array-valued cell
    const result: GenerateTruthTablesResult = {
      resultType: 'success',
      tables: [
        {
          tableId: 'policy',
          title: 'Array Test',
          policyType: 'scp',
          effectMode: 'denyOnly',
          testedAction: 's3:PutObject',
          testedResources: ['*'],
          columns: [
            { key: 'aws:PrincipalOrgPaths', label: 'Principal Org Paths', valueType: 'string' },
            { key: 'result', label: 'Result', valueType: 'result' }
          ],
          rows: [
            {
              rowId: 'row-1',
              cells: {
                'aws:PrincipalOrgPaths': ['o-example/r-root/ou-example/', 'o-other/r-root/'],
                result: 'Denied'
              },
              context: {
                'aws:PrincipalOrgPaths': ['o-example/r-root/ou-example/', 'o-other/r-root/']
              },
              result: {
                resultType: 'explicitlyDenied',
                label: 'Denied',
                matchedStatements: [{ index: 0, sid: 'Deny' }]
              }
            }
          ]
        }
      ],
      diagnostics: []
    }

    //When the result is rendered as Markdown
    const markdown = renderTruthTablesMarkdown(result)

    //Then the array should be rendered in a readable single table cell
    expect(markdown).toContain('| [o-example/r-root/ou-example/, o-other/r-root/] | Denied |')
  })

  it('should render any-value cells as Any', () => {
    //Given a successful result with a simplified summary row
    const result: GenerateTruthTablesResult = {
      resultType: 'success',
      tables: [
        {
          tableId: 'policy',
          title: 'Any Test',
          policyType: 'scp',
          effectMode: 'denyOnly',
          testedAction: 's3:PutObject',
          testedResources: ['*'],
          columns: [
            { key: 'aws:SecureTransport', label: 'Secure Transport', valueType: 'boolean' },
            { key: 'aws:RequestedRegion', label: 'Region', valueType: 'string' },
            { key: 'result', label: 'Result', valueType: 'result' }
          ],
          rows: [
            {
              rowType: 'summary',
              rowId: 'row-1',
              cells: {
                'aws:SecureTransport': false,
                'aws:RequestedRegion': { cellType: 'any', label: 'Any' },
                result: 'Denied'
              },
              result: {
                resultType: 'explicitlyDenied',
                label: 'Denied',
                matchedStatements: [{ index: 0, sid: 'Deny' }]
              },
              coveredRowCount: 2,
              coveredRowIds: ['row-1', 'row-2']
            }
          ]
        }
      ],
      diagnostics: []
    }

    //When the result is rendered as Markdown
    const markdown = renderTruthTablesMarkdown(result)

    //Then the any-value cell should render as Any
    expect(markdown).toContain('| false            | Any    | Denied |')
  })

  it('should render non-success diagnostics as markdown', () => {
    //Given a non-success result with diagnostics
    const result: GenerateTruthTablesResult = {
      resultType: 'invalidPolicy',
      diagnostics: [
        {
          severity: 'error',
          code: 'INVALID_POLICY',
          message: 'Effect is required'
        }
      ]
    }

    //When the result is rendered as Markdown
    const markdown = renderTruthTablesMarkdown(result)

    //Then it should include the diagnostics
    expect(markdown).toBe('# Invalid Policy\n\n- **error** `INVALID_POLICY`: Effect is required')
  })
})
