import { describe, expect, it } from 'vitest'
import { generateTruthTables } from './generateTruthTables.js'

const denyExternalS3DataAccessPolicy = {
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'DenyExternalS3DataAccess',
      Effect: 'Deny',
      Action: ['s3:PutObject', 's3:CopyObject'],
      Resource: '*',
      Condition: {
        StringNotEqualsIfExists: {
          'aws:ResourceOrgID': 'o-h2owf1zaat'
        },
        BoolIfExists: {
          'aws:ViaAWSService': 'false'
        }
      }
    }
  ]
}

describe('generateTruthTables', () => {
  it('should generate denied and not denied rows for a deny only SCP', async () => {
    //Given a deny-only SCP with organization and service-path conditions
    const policy = denyExternalS3DataAccessPolicy

    //When truth tables are generated
    const result = await generateTruthTables({ policy, policyType: 'scp' })

    //Then it should generate one policy table with meaningful row results
    expect(result.resultType).toBe('success')
    if (result.resultType !== 'success') {
      throw new Error('Expected success')
    }
    expect(result.tables[0].effectMode).toBe('denyOnly')
    expect(result.tables[0].testedAction).toBe('s3:PutObject')
    expect(result.tables[0].testedResources).toEqual(['*'])
    expect(result.tables[0].columns).toEqual([
      { key: 'aws:ResourceOrgID', label: 'Organization ID', valueType: 'string' },
      { key: 'aws:ViaAWSService', label: 'Is Via Service?', valueType: 'boolean' },
      { key: 'result', label: 'Result', valueType: 'result' }
    ])
    expect(
      result.tables[0].rows.map((row) => ({
        cells: row.cells,
        result: row.result
      }))
    ).toEqual([
      {
        cells: {
          'aws:ResourceOrgID': 'o-h2owf1zaat',
          'aws:ViaAWSService': false,
          result: 'Not Denied'
        },
        result: { resultType: 'notDenied', label: 'Not Denied' }
      },
      {
        cells: {
          'aws:ResourceOrgID': 'o-h2owf1zaat',
          'aws:ViaAWSService': true,
          result: 'Not Denied'
        },
        result: { resultType: 'notDenied', label: 'Not Denied' }
      },
      {
        cells: {
          'aws:ResourceOrgID': 'o-otherorg',
          'aws:ViaAWSService': false,
          result: 'Denied'
        },
        result: {
          resultType: 'explicitlyDenied',
          label: 'Denied',
          matchedStatements: [{ index: 0, sid: 'DenyExternalS3DataAccess' }]
        }
      },
      {
        cells: {
          'aws:ResourceOrgID': 'o-otherorg',
          'aws:ViaAWSService': true,
          result: 'Not Denied'
        },
        result: { resultType: 'notDenied', label: 'Not Denied' }
      },
      {
        cells: { 'aws:ResourceOrgID': null, 'aws:ViaAWSService': false, result: 'Denied' },
        result: {
          resultType: 'explicitlyDenied',
          label: 'Denied',
          matchedStatements: [{ index: 0, sid: 'DenyExternalS3DataAccess' }]
        }
      },
      {
        cells: { 'aws:ResourceOrgID': null, 'aws:ViaAWSService': true, result: 'Not Denied' },
        result: { resultType: 'notDenied', label: 'Not Denied' }
      }
    ])
  })

  it('should generate one row per scenario and resource with resource cells for multiple resources', async () => {
    //Given a deny-only SCP that matches one requested resource
    const policy = {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'DenyFirstObject',
          Effect: 'Deny',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::example-bucket/first.txt'
        }
      ]
    }

    //When truth tables are generated for two resources
    const result = await generateTruthTables({
      policy,
      policyType: 'scp',
      request: {
        action: 's3:GetObject',
        resources: [
          'arn:aws:s3:::example-bucket/first.txt',
          'arn:aws:s3:::example-bucket/second.txt'
        ]
      }
    })

    //Then the table should include one row for each requested resource
    expect(result.resultType).toBe('success')
    if (result.resultType !== 'success') {
      throw new Error('Expected success')
    }
    expect(result.tables[0].testedResources).toEqual([
      'arn:aws:s3:::example-bucket/first.txt',
      'arn:aws:s3:::example-bucket/second.txt'
    ])
    expect(result.tables[0].columns).toEqual([
      { key: 'resource', label: 'Resource', valueType: 'arn' },
      { key: 'result', label: 'Result', valueType: 'result' }
    ])
    expect(
      result.tables[0].rows.map((row) => ({
        rowId: row.rowId,
        cells: row.cells,
        result: row.result
      }))
    ).toEqual([
      {
        rowId: 'row-1',
        cells: {
          resource: 'arn:aws:s3:::example-bucket/first.txt',
          result: 'Denied'
        },
        result: {
          resultType: 'explicitlyDenied',
          label: 'Denied',
          matchedStatements: [{ index: 0, sid: 'DenyFirstObject' }]
        }
      },
      {
        rowId: 'row-2',
        cells: {
          resource: 'arn:aws:s3:::example-bucket/second.txt',
          result: 'Not Denied'
        },
        result: { resultType: 'notDenied', label: 'Not Denied' }
      }
    ])
  })

  it('should omit the resource column for one requested resource', async () => {
    //Given a deny-only SCP and one requested resource
    const policy = {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'DenyFirstObject',
          Effect: 'Deny',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::example-bucket/first.txt'
        }
      ]
    }

    //When truth tables are generated
    const result = await generateTruthTables({
      policy,
      policyType: 'scp',
      request: {
        action: 's3:GetObject',
        resources: ['arn:aws:s3:::example-bucket/first.txt']
      }
    })

    //Then the tested resource should be metadata, not a table column
    expect(result.resultType).toBe('success')
    if (result.resultType !== 'success') {
      throw new Error('Expected success')
    }
    expect(result.tables[0].testedResources).toEqual(['arn:aws:s3:::example-bucket/first.txt'])
    expect(result.tables[0].columns).toEqual([
      { key: 'result', label: 'Result', valueType: 'result' }
    ])
    expect(result.tables[0].rows[0].cells).toEqual({ result: 'Denied' })
  })

  it('should simplify identical multi-resource results to any resource', async () => {
    //Given a deny-only SCP with identical behavior across resources
    const policy = {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'DenyReads',
          Effect: 'Deny',
          Action: 's3:GetObject',
          Resource: '*'
        }
      ]
    }

    //When simplified truth tables are generated for two resources
    const result = await generateTruthTables({
      policy,
      policyType: 'scp',
      request: {
        action: 's3:GetObject',
        resources: [
          'arn:aws:s3:::example-bucket/first.txt',
          'arn:aws:s3:::example-bucket/second.txt'
        ]
      },
      options: { simplifyTables: true }
    })

    //Then the resource column should collapse to Any
    expect(result.resultType).toBe('success')
    if (result.resultType !== 'success') {
      throw new Error('Expected success')
    }
    expect(result.tables[0].rows).toEqual([
      {
        rowType: 'summary',
        rowId: 'row-1',
        cells: {
          resource: { cellType: 'any', label: 'Any' },
          result: 'Denied'
        },
        result: {
          resultType: 'explicitlyDenied',
          label: 'Denied',
          matchedStatements: [{ index: 0, sid: 'DenyReads' }]
        },
        coveredRowCount: 2,
        coveredRowIds: ['row-1', 'row-2']
      }
    ])
  })

  it('should return too many rows before simulation when the row limit is exceeded', async () => {
    //Given a low max row limit and two requested resources
    const policy = denyExternalS3DataAccessPolicy

    //When truth tables are generated
    const result = await generateTruthTables({
      policy,
      policyType: 'scp',
      request: {
        resources: [
          'arn:aws:s3:::example-bucket/first.txt',
          'arn:aws:s3:::example-bucket/second.txt'
        ]
      },
      options: { maxRows: 10 }
    })

    //Then it should return a tooManyRows result with row and resource counts
    expect(result).toEqual({
      resultType: 'tooManyRows',
      scenarioCount: 6,
      resourceCount: 2,
      rowCount: 12,
      maxRows: 10,
      diagnostics: [
        {
          severity: 'error',
          code: 'TOO_MANY_ROWS',
          message:
            'Generated 12 rows from 6 scenarios across 2 resources, exceeding the maximum of 10 rows.'
        }
      ]
    })
  })
})
