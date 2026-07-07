import { describe, expect, it } from 'vitest'
import { globalConditionKeyScenarioMetadata } from './globalConditionKeyMetadata.js'

describe('globalConditionKeyScenarioMetadata', () => {
  it.each([
    ['aws:PrincipalAccount', 'generatedSignedRequests'],
    ['aws:PrincipalArn', 'generatedSignedRequests'],
    ['aws:AssumedRoot', 'generatedScpRequests'],
    ['aws:PrincipalOrgID', 'generatedScpRequests'],
    ['aws:PrincipalOrgPaths', 'generatedScpRequests'],
    ['aws:PrincipalIsAWSService', 'generatedSignedRequests'],
    ['aws:PrincipalType', 'allRequests'],
    ['aws:userid', 'allRequests'],
    ['aws:ViaAWSService', 'allRequests'],
    ['aws:CurrentTime', 'allRequests'],
    ['aws:EpochTime', 'allRequests'],
    ['aws:RequestedRegion', 'allRequests'],
    ['aws:SecureTransport', 'allRequests'],
    ['aws:SourceAccount', 'generatedScpRequests'],
    ['aws:SourceArn', 'generatedScpRequests'],
    ['aws:SourceOwner', 'generatedScpRequests'],
    ['aws:SourceOrgID', 'generatedScpRequests'],
    ['aws:SourceOrgPaths', 'generatedScpRequests'],
    ['aws:UserAgent', 'allRequests']
  ] as const)(
    'should declare %s as not missing from %s request context',
    (conditionKey, presenceScope) => {
      //When metadata is looked up
      const result = globalConditionKeyScenarioMetadata(conditionKey)

      //Then the metadata should indicate it cannot be missing
      expect(result).toMatchObject({ key: conditionKey, presenceScope })
    }
  )

  it('should override AssumedRoot value type to boolean for generated scenarios', () => {
    //Given AssumedRoot has corrected truth-table metadata
    const conditionKey = 'aws:AssumedRoot'

    //When metadata is looked up
    const result = globalConditionKeyScenarioMetadata(conditionKey)

    //Then generated scenario metadata should use a boolean cell type
    expect(result).toMatchObject({ key: conditionKey, valueType: 'boolean' })
  })

  it.each([
    'aws:SourceAccount',
    'aws:SourceArn',
    'aws:SourceOwner',
    'aws:SourceOrgID',
    'aws:SourceOrgPaths'
  ])('should mark %s as missing-only for generated SCP requests', (conditionKey) => {
    //When metadata is looked up
    const result = globalConditionKeyScenarioMetadata(conditionKey)

    //Then generated SCP scenarios should only include the missing-key case
    expect(result).toEqual({
      key: conditionKey,
      canBeMissing: true,
      presenceScope: 'generatedScpRequests',
      scenarioValueMode: 'missingOnly'
    })
  })

  it('should look up maintained global condition key metadata case-insensitively', () => {
    //Given an always-present global condition key with mixed casing
    const conditionKey = 'AWS:SecureTransport'

    //When metadata is looked up
    const result = globalConditionKeyScenarioMetadata(conditionKey)

    //Then the canonical metadata should be returned
    expect(result).toEqual({
      key: 'aws:SecureTransport',
      canBeMissing: false,
      presenceScope: 'allRequests'
    })
  })

  it('should return undefined for keys without maintained metadata', () => {
    //Given a key without maintained metadata
    const conditionKey = 'aws:ResourceOrgID'

    //When metadata is looked up
    const result = globalConditionKeyScenarioMetadata(conditionKey)

    //Then no metadata should be returned
    expect(result).toBeUndefined()
  })
})
