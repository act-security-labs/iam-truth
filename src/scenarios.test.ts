import { describe, expect, it } from 'vitest'
import { extractConditionKeys } from './conditionKeys.js'
import {
  firstNonMatchingLikeValue,
  generateScenarios,
  matchingLikeValue,
  matchesLikePattern
} from './scenarios.js'

const examplePolicy = {
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

describe('generateScenarios', () => {
  it('should generate policy value alternate value and meaningful missing scenarios', async () => {
    //Given condition keys from the example policy
    const conditionKeys = extractConditionKeys(examplePolicy)

    //When scenarios are generated
    const result = await generateScenarios(conditionKeys)

    //Then ResourceOrgID should include policy, alternate, and missing values while ViaAWSService has booleans
    expect(result.scenarios.map((scenario) => scenario.cells)).toEqual([
      { 'aws:ResourceOrgID': 'o-h2owf1zaat', 'aws:ViaAWSService': false },
      { 'aws:ResourceOrgID': 'o-h2owf1zaat', 'aws:ViaAWSService': true },
      { 'aws:ResourceOrgID': 'o-otherorg', 'aws:ViaAWSService': false },
      { 'aws:ResourceOrgID': 'o-otherorg', 'aws:ViaAWSService': true },
      { 'aws:ResourceOrgID': null, 'aws:ViaAWSService': false },
      { 'aws:ResourceOrgID': null, 'aws:ViaAWSService': true }
    ])
    expect(result.scenarios[4].context).toEqual({ 'aws:ViaAWSService': 'false' })
  })

  it('should generate ForAllValues scenarios for multivalue condition keys', async () => {
    //Given a multivalue condition key with a ForAllValues operator
    const conditionKeys = extractConditionKeys({
      Statement: [
        {
          Effect: 'Deny',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: {
            'ForAllValues:StringEquals': {
              'aws:PrincipalOrgPaths': 'o-example/r-root/ou-example/'
            }
          }
        }
      ]
    })

    //When scenarios are generated
    const result = await generateScenarios(conditionKeys)

    //Then none, some, and all multivalue scenarios should be generated
    expect(result.scenarios.map((scenario) => scenario.cells)).toEqual([
      { 'aws:PrincipalOrgPaths': ['o-otherorg/r-root/ou-root-sandbox/'] },
      {
        'aws:PrincipalOrgPaths': [
          'o-example/r-root/ou-example/',
          'o-otherorg/r-root/ou-root-sandbox/'
        ]
      },
      { 'aws:PrincipalOrgPaths': ['o-example/r-root/ou-example/'] }
    ])
    expect(result.scenarios[1].context).toEqual({
      'aws:PrincipalOrgPaths': [
        'o-example/r-root/ou-example/',
        'o-otherorg/r-root/ou-root-sandbox/'
      ]
    })
  })

  it('should generate ForAnyValues scenarios for multivalue condition keys', async () => {
    //Given a multivalue condition key with a ForAnyValue operator
    const conditionKeys = extractConditionKeys({
      Statement: [
        {
          Effect: 'Deny',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: {
            'ForAnyValue:StringEquals': {
              'aws:PrincipalOrgPaths': 'o-example/r-root/ou-example/'
            }
          }
        }
      ]
    })

    //When scenarios are generated
    const result = await generateScenarios(conditionKeys)

    //Then none, one, and all multivalue scenarios should be generated
    expect(result.scenarios.map((scenario) => scenario.cells)).toEqual([
      { 'aws:PrincipalOrgPaths': ['o-otherorg/r-root/ou-root-sandbox/'] },
      {
        'aws:PrincipalOrgPaths': [
          'o-example/r-root/ou-example/',
          'o-otherorg/r-root/ou-root-sandbox/'
        ]
      },
      { 'aws:PrincipalOrgPaths': ['o-example/r-root/ou-example/'] }
    ])
  })

  it('should generate a non-matching alternate for Like operators', async () => {
    //Given a Like operator with a wildcard pattern
    const conditionKeys = extractConditionKeys({
      Statement: [
        {
          Effect: 'Deny',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: {
            StringLike: {
              'aws:UserAgent': 'act-security-*'
            }
          }
        }
      ]
    })

    //When scenarios are generated
    const result = await generateScenarios(conditionKeys)

    //Then the alternate scenario should not match the policy pattern
    expect(result.scenarios.map((scenario) => scenario.cells)).toEqual([
      { 'aws:UserAgent': 'act-security-example' },
      { 'aws:UserAgent': 'not-act-security-example' }
    ])
  })

  it('should generate account-shaped matching values for ArnLike account wildcards', async () => {
    //Given an ArnLike operator with a wildcard account-id segment
    const conditionKeys = extractConditionKeys({
      Statement: [
        {
          Effect: 'Deny',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: {
            ArnLike: {
              'aws:PrincipalArn': 'arn:aws:iam::*:root'
            }
          }
        }
      ]
    })

    //When scenarios are generated
    const result = await generateScenarios(conditionKeys)

    //Then the matching scenario should use a valid-looking AWS account root ARN
    expect(result.scenarios.map((scenario) => scenario.cells)).toEqual([
      { 'aws:PrincipalArn': 'arn:aws:iam::111111111111:root' },
      { 'aws:PrincipalArn': 'arn:aws:iam::222222222222:role/OtherRole' }
    ])
  })

  it('should keep set-operator scenarios scalar for scalar condition keys', async () => {
    //Given a scalar condition key with a ForAnyValue operator
    const conditionKeys = extractConditionKeys({
      Statement: [
        {
          Effect: 'Deny',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: {
            'ForAnyValue:StringEquals': {
              'aws:UserAgent': 'act-security-example-value'
            }
          }
        }
      ]
    })

    //When scenarios are generated
    const result = await generateScenarios(conditionKeys)

    //Then scalar metadata should prevent multivalue array generation
    expect(result.scenarios.map((scenario) => scenario.cells)).toEqual([
      { 'aws:UserAgent': 'act-security-example-value' },
      { 'aws:UserAgent': 'aws-sdk-js/3.x' }
    ])
  })

  it('should generate present and missing scenarios for Null operators', async () => {
    //Given a Null operator that checks whether a context key is absent
    const conditionKeys = extractConditionKeys({
      Statement: [
        {
          Effect: 'Deny',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: {
            Null: {
              'aws:SourceIdentity': 'true'
            }
          }
        }
      ]
    })

    //When scenarios are generated
    const result = await generateScenarios(conditionKeys)

    //Then missing and present scenarios should be generated with arbitrary present context values
    expect(result.scenarios.map((scenario) => scenario.cells)).toEqual([
      { 'aws:SourceIdentity': null },
      { 'aws:SourceIdentity': 'alice' }
    ])
  })

  it('should generate boolean present values for Null operators on boolean keys', async () => {
    //Given a Null operator that checks whether a boolean context key is absent
    const conditionKeys = extractConditionKeys({
      Statement: [
        {
          Effect: 'Deny',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: {
            Null: {
              'aws:AssumedRoot': 'true'
            }
          }
        }
      ]
    })

    //When scenarios are generated
    const result = await generateScenarios(conditionKeys)

    //Then missing and present scenarios should be generated with a typed boolean present value
    expect(result.scenarios.map((scenario) => scenario.cells)).toEqual([
      { 'aws:AssumedRoot': null },
      { 'aws:AssumedRoot': true }
    ])
    expect(result.scenarios[1].context).toEqual({ 'aws:AssumedRoot': 'true' })
  })

  it('should generate supported RCP Null-operator scenarios for resource-info key availability', async () => {
    //Given Null operators for resource-info keys on a supported generated RCP action
    const conditionKeys = extractConditionKeys({
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: '*',
          Condition: {
            Null: {
              'aws:ResourceAccount': 'true',
              'aws:ResourceOrgID': 'true',
              'aws:ResourceOrgPaths': 'true'
            }
          }
        }
      ]
    })

    //When scenarios are generated with supported RCP request metadata
    const result = await generateScenarios(conditionKeys, {
      requestContext: {
        policyType: 'rcp',
        requestModel: 'generatedSignedRcpRequest',
        action: 's3:GetObject',
        resource: 'arn:aws:s3:::example-bucket/example.txt'
      }
    })

    //Then ResourceAccount should be present-only while organization keys also include missing scenarios
    expect(result.scenarios.map((scenario) => scenario.cells)).toEqual([
      {
        'aws:ResourceAccount': '111111111111',
        'aws:ResourceOrgID': null,
        'aws:ResourceOrgPaths': null
      },
      {
        'aws:ResourceAccount': '111111111111',
        'aws:ResourceOrgID': null,
        'aws:ResourceOrgPaths': 'o-exampleorg/r-root/ou-root-security/'
      },
      {
        'aws:ResourceAccount': '111111111111',
        'aws:ResourceOrgID': 'o-exampleorg',
        'aws:ResourceOrgPaths': null
      },
      {
        'aws:ResourceAccount': '111111111111',
        'aws:ResourceOrgID': 'o-exampleorg',
        'aws:ResourceOrgPaths': 'o-exampleorg/r-root/ou-root-security/'
      }
    ])
    expect(result.scenarios[0].context).toEqual({
      'aws:ResourceAccount': '111111111111'
    })
    expect(result.scenarios[3].context).toEqual({
      'aws:ResourceAccount': '111111111111',
      'aws:ResourceOrgID': 'o-exampleorg',
      'aws:ResourceOrgPaths': ['o-exampleorg/r-root/ou-root-security/']
    })
  })

  it('should generate same above below and missing scenarios for numeric comparison operators', async () => {
    //Given a numeric less-than operator
    const conditionKeys = extractConditionKeys({
      Statement: [
        {
          Effect: 'Deny',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: {
            NumericLessThan: {
              'aws:MultiFactorAuthAge': '5'
            }
          }
        }
      ]
    })

    //When scenarios are generated
    const result = await generateScenarios(conditionKeys)

    //Then one below, same, one above, and missing scenarios should be generated
    expect(result.scenarios.map((scenario) => scenario.cells)).toEqual([
      { 'aws:MultiFactorAuthAge': 4 },
      { 'aws:MultiFactorAuthAge': 5 },
      { 'aws:MultiFactorAuthAge': 6 },
      { 'aws:MultiFactorAuthAge': null }
    ])
  })

  it('should generate one representative matching row by default for scalar keys with multiple policy values', async () => {
    //Given a single-valued context key with multiple policy values
    const conditionKeys = extractConditionKeys({
      Statement: [
        {
          Effect: 'Deny',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: {
            StringEquals: {
              'aws:ResourceTag/dept': ['accounting', 'sales']
            }
          }
        }
      ]
    })

    //When scenarios are generated with default options
    const result = await generateScenarios(conditionKeys)

    //Then only the first policy value should get a matching row
    expect(result.scenarios.map((scenario) => scenario.cells)).toEqual([
      { 'aws:ResourceTag/dept': 'accounting' },
      { 'aws:ResourceTag/dept': 'finance' },
      { 'aws:ResourceTag/dept': null }
    ])
  })

  it('should generate one matching row per policy value when requested', async () => {
    //Given a single-valued context key with multiple policy values
    const conditionKeys = extractConditionKeys({
      Statement: [
        {
          Effect: 'Deny',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: {
            StringEquals: {
              'aws:ResourceTag/dept': ['accounting', 'sales']
            }
          }
        }
      ]
    })

    //When scenarios are generated with all policy value examples shown
    const result = await generateScenarios(conditionKeys, {
      showExamplesForAllPolicyValues: true
    })

    //Then each policy value should get a scalar matching row plus non-match and missing rows
    expect(result.scenarios.map((scenario) => scenario.cells)).toEqual([
      { 'aws:ResourceTag/dept': 'accounting' },
      { 'aws:ResourceTag/dept': 'sales' },
      { 'aws:ResourceTag/dept': 'finance' },
      { 'aws:ResourceTag/dept': null }
    ])
  })

  it('should generate one representative matching Like pattern row by default', async () => {
    //Given a single-valued context key with multiple Like patterns
    const conditionKeys = extractConditionKeys({
      Statement: [
        {
          Effect: 'Deny',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: {
            StringLike: {
              'aws:ResourceTag/dept': ['sales/*', 'acct/*']
            }
          }
        }
      ]
    })

    //When scenarios are generated with default options
    const result = await generateScenarios(conditionKeys)

    //Then only the first pattern should get a matching row and the non-match should avoid all patterns
    expect(result.scenarios.map((scenario) => scenario.cells)).toEqual([
      { 'aws:ResourceTag/dept': 'sales/example' },
      { 'aws:ResourceTag/dept': 'not-sales/example' },
      { 'aws:ResourceTag/dept': null }
    ])
    expect(matchesLikePattern('not-sales/example', 'sales/*')).toBe(false)
    expect(matchesLikePattern('not-sales/example', 'acct/*')).toBe(false)
  })

  it('should generate one matching row per Like pattern when requested', async () => {
    //Given a single-valued context key with multiple Like patterns
    const conditionKeys = extractConditionKeys({
      Statement: [
        {
          Effect: 'Deny',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: {
            StringLike: {
              'aws:ResourceTag/dept': ['sales/*', 'acct/*']
            }
          }
        }
      ]
    })

    //When scenarios are generated with all policy value examples shown
    const result = await generateScenarios(conditionKeys, {
      showExamplesForAllPolicyValues: true
    })

    //Then each pattern should get a matching row
    expect(result.scenarios.map((scenario) => scenario.cells)).toEqual([
      { 'aws:ResourceTag/dept': 'sales/example' },
      { 'aws:ResourceTag/dept': 'acct/example' },
      { 'aws:ResourceTag/dept': 'not-sales/example' },
      { 'aws:ResourceTag/dept': null }
    ])
  })

  it('should generate a distinct alternate value when a policy uses the generic example value', async () => {
    //Given a policy that already uses the generic example value
    const conditionKeys = extractConditionKeys({
      Statement: [
        {
          Effect: 'Deny',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: {
            StringEqualsIfExists: {
              'aws:SourceVpc': 'act-security-example-value'
            }
          }
        }
      ]
    })

    //When scenarios are generated
    const result = await generateScenarios(conditionKeys)

    //Then the generated alternate should not collapse into the policy value
    expect(result.scenarios.map((scenario) => scenario.cells)).toEqual([
      { 'aws:SourceVpc': 'act-security-example-value' },
      { 'aws:SourceVpc': 'vpc-0fedcba9876543210' },
      { 'aws:SourceVpc': null }
    ])
  })
})

describe('StringLike scenario value helpers', () => {
  it.each([
    ['act-security-*', 'act-security-example'],
    ['*-suffix', 'example-suffix'],
    ['prefix-*', 'prefix-example'],
    ['prefix-*-suffix', 'prefix-example-suffix'],
    ['prefix-?-suffix', 'prefix-x-suffix'],
    ['?-suffix', 'x-suffix'],
    ['prefix-?', 'prefix-x'],
    ['arn:aws:s3:::bucket/*', 'arn:aws:s3:::bucket/example']
  ])('should create a matching value for pattern %s', (pattern, expected) => {
    //When a matching Like value is generated
    const result = matchingLikeValue(pattern)

    //Then it should match the original pattern
    expect(result).toBe(expected)
    expect(matchesLikePattern(result, pattern)).toBe(true)
  })

  it.each([
    ['act-security-*'],
    ['*-suffix'],
    ['prefix-*'],
    ['prefix-*-suffix'],
    ['prefix-?-suffix'],
    ['?-suffix'],
    ['prefix-?'],
    ['arn:aws:s3:::bucket/*']
  ])('should create a non-matching value for pattern %s', (pattern) => {
    //When a non-matching Like value is generated
    const result = firstNonMatchingLikeValue([pattern])

    //Then it should not match the original pattern
    expect(matchesLikePattern(result, pattern)).toBe(false)
  })

  it('should create a value that avoids all policy Like patterns', () => {
    //Given multiple Like patterns for the same condition key
    const patterns = ['act-security-*', '*-suffix', 'prefix-?-middle']

    //When a non-matching Like value is generated
    const result = firstNonMatchingLikeValue(patterns)

    //Then it should not match any policy pattern
    expect(patterns.some((pattern) => matchesLikePattern(result, pattern))).toBe(false)
  })

  it('should match question mark wildcards as exactly one character', () => {
    //Given a pattern with a question-mark wildcard
    const pattern = 'prefix-?-suffix'

    //When concrete values are checked
    const oneCharacter = matchesLikePattern('prefix-x-suffix', pattern)
    const twoCharacters = matchesLikePattern('prefix-xy-suffix', pattern)

    //Then only the single-character value should match
    expect(oneCharacter).toBe(true)
    expect(twoCharacters).toBe(false)
  })
})
