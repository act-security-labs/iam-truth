import { describe, expect, it } from 'vitest'
import { buildRcpSimulation, simulateScenario } from './simulation.js'
import { type JsonPolicyDocument } from './types.js'

const baselineRequest = {
  principal: 'arn:aws:iam::111111111111:role/TestRole',
  action: 's3:GetObject',
  resource: 'arn:aws:s3:::example-bucket/example.txt'
}

const scenario = {
  scenarioId: 'row-1',
  cells: {},
  context: {}
}

describe('buildRcpSimulation', () => {
  it('should place target policies in resource control policies', () => {
    //Given an RCP policy document
    const policy: JsonPolicyDocument = {
      Version: '2012-10-17',
      Statement: [{ Effect: 'Deny', Principal: '*', Action: 's3:GetObject', Resource: '*' }]
    }

    //When an RCP simulation is built
    const result = buildRcpSimulation(policy, baselineRequest, scenario)

    //Then the target policy should be configured as an RCP, not an SCP
    expect(result.serviceControlPolicies).toEqual([])
    expect(result.resourceControlPolicies).toEqual([
      { orgIdentifier: 'ou-iam-truth', policies: [{ name: 'TargetPolicy', policy }] }
    ])
    expect(result.identityPolicies).toEqual([
      {
        name: 'GeneratedIdentityAllowAll',
        policy: {
          Version: '2012-10-17',
          Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }]
        }
      }
    ])
  })
})

describe('simulateScenario', () => {
  it('should map matched RCP deny statements from rcp analysis', async () => {
    //Given an RCP that explicitly denies the request
    const policy: JsonPolicyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'DenyObjectRead',
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: '*'
        }
      ]
    }

    //When the scenario is simulated as an RCP
    const result = await simulateScenario('rcp', policy, 'denyOnly', baselineRequest, scenario)

    //Then the denied row should include the matched RCP statement index and Sid
    expect(result).toEqual({
      resultType: 'success',
      rowResult: {
        resultType: 'explicitlyDenied',
        label: 'Denied',
        matchedStatements: [{ index: 0, sid: 'DenyObjectRead' }]
      },
      diagnostics: []
    })
  })

  it('should map matched deny statements without Sids to statement indexes', async () => {
    //Given an RCP that explicitly denies the request with no statement Sid
    const policy: JsonPolicyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: '*'
        }
      ]
    }

    //When the scenario is simulated as an RCP
    const result = await simulateScenario('rcp', policy, 'denyOnly', baselineRequest, scenario)

    //Then the denied row should include the zero-based statement index without a Sid
    expect(result).toEqual({
      resultType: 'success',
      rowResult: {
        resultType: 'explicitlyDenied',
        label: 'Denied',
        matchedStatements: [{ index: 0 }]
      },
      diagnostics: []
    })
  })
})
