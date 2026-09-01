import { loadPolicy } from '@actsecurity/iam-policy'
import { describe, expect, it } from 'vitest'
import { statementsApplicableToAction } from './actionFilter.js'

describe('statementsApplicableToAction', () => {
  it('should keep only statements that can apply to the tested action', () => {
    //Given a policy with conditions on matching and non-matching actions
    const policy = loadPolicy({
      Statement: [
        {
          Sid: 'Applies',
          Effect: 'Deny',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: { StringEquals: { 'aws:ResourceOrgID': 'o-example' } }
        },
        {
          Sid: 'DoesNotApply',
          Effect: 'Deny',
          Action: 'ec2:StartInstances',
          Resource: '*',
          Condition: { StringEquals: { 'aws:RequestedRegion': 'us-east-1' } }
        },
        {
          Sid: 'NotActionApplies',
          Effect: 'Deny',
          NotAction: 'ec2:*',
          Resource: '*',
          Condition: { Bool: { 'aws:SecureTransport': 'false' } }
        }
      ]
    })

    //When statements are filtered to the tested action
    const result = statementsApplicableToAction(policy.statements(), 's3:PutObject')

    //Then only matching Action and applicable NotAction statements should remain
    expect(result.map((statement) => statement.sid())).toEqual(['Applies', 'NotActionApplies'])
  })
})
