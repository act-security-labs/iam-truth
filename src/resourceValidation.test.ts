import { describe, expect, it } from 'vitest'
import { validateResourcesForAction } from './resourceValidation.js'

describe('validateResourcesForAction', () => {
  it('should partition resources by action-supported resource types', async () => {
    //Given an S3 object action with one object ARN and one IAM role ARN
    const resources = [
      'arn:aws:s3:::example-bucket/example.txt',
      'arn:aws:iam::111111111111:role/TestRole'
    ]

    //When resources are validated for the action
    const result = await validateResourcesForAction('s3:GetObject', resources)

    //Then the object should be testable and the role should be untested
    expect(result).toEqual({
      resultType: 'validated',
      testableResources: ['arn:aws:s3:::example-bucket/example.txt'],
      untestedResources: [
        {
          resource: 'arn:aws:iam::111111111111:role/TestRole',
          reason: 'unsupportedForAction',
          action: 's3:GetObject',
          supportedResourceTypes: [
            {
              name: 'accesspointobject',
              arnPattern:
                'arn:${Partition}:s3:${Region}:${Account}:accesspoint/${AccessPointName}/object/${ObjectName}'
            },
            { name: 'object', arnPattern: 'arn:${Partition}:s3:::${BucketName}/${ObjectName}' }
          ]
        }
      ]
    })
  })

  it('should always allow the wildcard resource', async () => {
    //Given a wildcard resource for an object action
    const resources = ['*']

    //When resources are validated
    const result = await validateResourcesForAction('s3:GetObject', resources)

    //Then the wildcard should be testable
    expect(result).toEqual({
      resultType: 'validated',
      testableResources: ['*'],
      untestedResources: []
    })
  })

  it('should only allow wildcard resources for wildcard-only actions', async () => {
    //Given a wildcard-only action with a wildcard and a concrete ARN
    const resources = ['*', 'arn:aws:s3:::example-bucket']

    //When resources are validated
    const result = await validateResourcesForAction('s3:ListAllMyBuckets', resources)

    //Then only the wildcard should be testable
    expect(result).toEqual({
      resultType: 'validated',
      testableResources: ['*'],
      untestedResources: [
        {
          resource: 'arn:aws:s3:::example-bucket',
          reason: 'unsupportedForAction',
          action: 's3:ListAllMyBuckets',
          supportedResourceTypes: []
        }
      ]
    })
  })

  it('should preserve duplicate untestable resources', async () => {
    //Given duplicate resources that are unsupported for an action
    const resources = [
      'arn:aws:iam::111111111111:role/TestRole',
      'arn:aws:iam::111111111111:role/TestRole'
    ]

    //When resources are validated
    const result = await validateResourcesForAction('s3:GetObject', resources)

    //Then both duplicate untestable resources should be retained
    expect(result.resultType).toBe('validated')
    if (result.resultType !== 'validated') {
      throw new Error('Expected validated result')
    }
    expect(result.testableResources).toEqual([])
    expect(result.untestedResources.map((resource) => resource.resource)).toEqual(resources)
  })

  it('should skip validation when action metadata is unavailable', async () => {
    //Given an unknown action
    const resources = ['arn:aws:s3:::example-bucket/example.txt']

    //When resources are validated
    const result = await validateResourcesForAction('example:DoesNotExist', resources)

    //Then validation should be skipped so existing simulation behavior can handle the action
    expect(result).toEqual({ resultType: 'actionMetadataUnavailable' })
  })

  it('should skip validation for malformed or wildcarded actions', async () => {
    //Given malformed and wildcarded action strings
    const resources = ['arn:aws:s3:::example-bucket/example.txt']

    //When resources are validated
    const missingColon = await validateResourcesForAction('s3GetObject', resources)
    const wildcarded = await validateResourcesForAction('s3:*', resources)

    //Then validation should be skipped
    expect(missingColon).toEqual({ resultType: 'actionMetadataUnavailable' })
    expect(wildcarded).toEqual({ resultType: 'actionMetadataUnavailable' })
  })
})
