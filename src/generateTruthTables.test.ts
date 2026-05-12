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
          matchedStatementIds: ['DenyExternalS3DataAccess']
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
          matchedStatementIds: ['DenyExternalS3DataAccess']
        }
      },
      {
        cells: { 'aws:ResourceOrgID': null, 'aws:ViaAWSService': true, result: 'Not Denied' },
        result: { resultType: 'notDenied', label: 'Not Denied' }
      }
    ])
  })

  it('should return too many scenarios before simulation when the row limit is exceeded', async () => {
    //Given a low max row limit
    const policy = denyExternalS3DataAccessPolicy

    //When truth tables are generated
    const result = await generateTruthTables({ policy, policyType: 'scp', options: { maxRows: 1 } })

    //Then it should return a tooManyScenarios result with a diagnostic
    expect(result).toEqual({
      resultType: 'tooManyScenarios',
      scenarioCount: 6,
      maxScenarios: 1,
      diagnostics: [
        {
          severity: 'error',
          code: 'TOO_MANY_SCENARIOS',
          message: 'Generated 6 scenarios, exceeding the maximum of 1.'
        }
      ]
    })
  })
})
