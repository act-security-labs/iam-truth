import { describe, expect, it } from 'vitest'
import {
  defaultAction,
  resolveBaselineRequest,
  DEFAULT_PRINCIPAL,
  DEFAULT_RESOURCE
} from './requestDefaults.js'

describe('defaultAction', () => {
  it('should use the first expanded action from the first Action statement', async () => {
    //Given a policy with multiple actions in the first statement
    const policy = {
      Statement: [{ Effect: 'Deny', Action: ['s3:PutObject', 's3:CopyObject'], Resource: '*' }]
    }

    //When the default action is determined
    const result = await defaultAction(policy)

    //Then it should use the first expanded action
    expect(result).toBe('s3:PutObject')
  })

  it('should invert NotAction statements so the inferred action applies to the statement', async () => {
    //Given allow and deny policies with NotAction
    const allowPolicy = { Statement: [{ Effect: 'Allow', NotAction: 's3:*', Resource: '*' }] }
    const denyPolicy = { Statement: [{ Effect: 'Deny', NotAction: 's3:GetObject', Resource: '*' }] }

    //When the default actions are determined
    const allowResult = await defaultAction(allowPolicy)
    const denyResult = await defaultAction(denyPolicy)

    //Then both inferred actions should be outside the NotAction exclusions
    expect(allowResult).not.toMatch(/^s3:/)
    expect(denyResult).not.toBe('s3:GetObject')
  })
})

describe('resolveBaselineRequest', () => {
  it('should apply caller overrides and deterministic defaults', async () => {
    //Given a policy and partial request overrides
    const policy = { Statement: [{ Effect: 'Deny', Action: 's3:PutObject', Resource: '*' }] }

    //When the baseline request is resolved
    const result = await resolveBaselineRequest(policy, {
      resources: ['arn:aws:s3:::examplebucket/*']
    })

    //Then it should combine inferred defaults with caller overrides
    expect(result).toEqual({
      resultType: 'success',
      request: {
        action: 's3:PutObject',
        resource: 'arn:aws:s3:::examplebucket/*',
        principal: DEFAULT_PRINCIPAL
      },
      resources: ['arn:aws:s3:::examplebucket/*']
    })
    expect(DEFAULT_RESOURCE).toBe('*')
  })

  it('should preserve multiple requested resources in order including duplicates', async () => {
    //Given a policy and duplicate resource overrides
    const policy = { Statement: [{ Effect: 'Deny', Action: 's3:PutObject', Resource: '*' }] }

    //When the baseline request is resolved
    const result = await resolveBaselineRequest(policy, {
      resources: [
        'arn:aws:s3:::examplebucket/first',
        'arn:aws:s3:::examplebucket/second',
        'arn:aws:s3:::examplebucket/first'
      ]
    })

    //Then it should preserve requested resource order and use the first resource as the baseline
    expect(result).toEqual({
      resultType: 'success',
      request: {
        action: 's3:PutObject',
        resource: 'arn:aws:s3:::examplebucket/first',
        principal: DEFAULT_PRINCIPAL
      },
      resources: [
        'arn:aws:s3:::examplebucket/first',
        'arn:aws:s3:::examplebucket/second',
        'arn:aws:s3:::examplebucket/first'
      ]
    })
  })

  it('should default undefined and empty resources to the wildcard resource', async () => {
    //Given a policy without explicit resource overrides
    const policy = { Statement: [{ Effect: 'Deny', Action: 's3:PutObject', Resource: '*' }] }

    //When baseline requests are resolved
    const undefinedResult = await resolveBaselineRequest(policy, undefined)
    const emptyResult = await resolveBaselineRequest(policy, { resources: [] })

    //Then both should use the wildcard resource
    expect(undefinedResult).toEqual({
      resultType: 'success',
      request: {
        action: 's3:PutObject',
        resource: DEFAULT_RESOURCE,
        principal: DEFAULT_PRINCIPAL
      },
      resources: [DEFAULT_RESOURCE]
    })
    expect(emptyResult).toEqual(undefinedResult)
  })
})
