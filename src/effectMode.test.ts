import { describe, expect, it } from 'vitest'
import { policyEffectMode } from './effectMode.js'

describe('policyEffectMode', () => {
  it('should detect a deny only policy', () => {
    //Given a policy with only Deny statements
    const policy = { Statement: [{ Effect: 'Deny', Action: '*', Resource: '*' }] }

    //When the effect mode is calculated
    const result = policyEffectMode(policy)

    //Then it should be denyOnly
    expect(result).toBe('denyOnly')
  })

  it('should detect an allow only policy', () => {
    //Given a policy with only Allow statements
    const policy = { Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }

    //When the effect mode is calculated
    const result = policyEffectMode(policy)

    //Then it should be allowOnly
    expect(result).toBe('allowOnly')
  })

  it('should detect a policy with allow and deny statements', () => {
    //Given a policy with Allow and Deny statements
    const policy = {
      Statement: [
        { Effect: 'Allow', Action: '*', Resource: '*' },
        { Effect: 'Deny', Action: 's3:*', Resource: '*' }
      ]
    }

    //When the effect mode is calculated
    const result = policyEffectMode(policy)

    //Then it should be allowAndDeny
    expect(result).toBe('allowAndDeny')
  })
})
