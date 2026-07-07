import { describe, expect, it } from 'vitest'
import {
  fakeConditionKeyValue,
  firstDistinctString,
  type FakeConditionKeyValueRequest
} from './conditionKeyFakeValues.js'

interface FakeConditionKeyValueCase {
  name: string
  request: FakeConditionKeyValueRequest
  expected: string
}

const fakeConditionKeyValueCases: FakeConditionKeyValueCase[] = [
  {
    name: 'principal ARN alternate uses IAM role ARN',
    request: fakeValueRequest('aws:PrincipalArn', 'arn', 'alternate'),
    expected: 'arn:aws:iam::222222222222:role/OtherRole'
  },
  {
    name: 'source ARN matching fallback uses S3 bucket ARN',
    request: fakeValueRequest('aws:SourceArn', 'arn', 'matchingFallback'),
    expected: 'arn:aws:s3:::example-bucket'
  },
  {
    name: 'chatbot source ARN alternate uses Chatbot ARN',
    request: fakeValueRequest('aws:ChatbotSourceArn', 'arn', 'alternate'),
    expected: 'arn:aws:chatbot::222222222222:chat-configuration/slack-channel/other'
  },
  {
    name: 'EC2 source instance ARN alternate uses EC2 instance ARN',
    request: fakeValueRequest('ec2:SourceInstanceArn', 'arn', 'alternate'),
    expected: 'arn:aws:ec2:us-west-2:222222222222:instance/i-0fedcba9876543210'
  },
  {
    name: 'Lambda source function ARN alternate uses Lambda function ARN',
    request: fakeValueRequest('lambda:SourceFunctionArn', 'arn', 'alternate'),
    expected: 'arn:aws:lambda:us-west-2:222222222222:function:other-function'
  },
  {
    name: 'SSM source instance ARN alternate uses managed instance ARN',
    request: fakeValueRequest('ssm:SourceInstanceArn', 'arn', 'alternate'),
    expected: 'arn:aws:ssm:us-west-2:222222222222:managed-instance/mi-0fedcba9876543210'
  },
  {
    name: 'source VPC ARN alternate uses VPC ARN even though key is string typed',
    request: fakeValueRequest('aws:SourceVpcArn', 'string', 'alternate'),
    expected: 'arn:aws:ec2:us-west-2:222222222222:vpc/vpc-0fedcba9876543210'
  },
  {
    name: 'source VPC alternate uses VPC ID',
    request: fakeValueRequest('aws:SourceVpc', 'string', 'alternate'),
    expected: 'vpc-0fedcba9876543210'
  },
  {
    name: 'EC2 instance source VPC present value uses VPC ID',
    request: fakeValueRequest('aws:Ec2InstanceSourceVpc', 'string', 'present'),
    expected: 'vpc-0123456789abcdef0'
  },
  {
    name: 'source VPC endpoint alternate uses endpoint ID',
    request: fakeValueRequest('aws:SourceVpce', 'string', 'alternate'),
    expected: 'vpce-0fedcba9876543210'
  },
  {
    name: 'principal account alternate uses AWS account ID',
    request: fakeValueRequest('aws:PrincipalAccount', 'string', 'alternate'),
    expected: '222222222222'
  },
  {
    name: 'resource account matching fallback uses AWS account ID',
    request: fakeValueRequest('aws:ResourceAccount', 'string', 'matchingFallback'),
    expected: '111111111111'
  },
  {
    name: 'source owner alternate uses AWS account ID',
    request: fakeValueRequest('aws:SourceOwner', 'string', 'alternate'),
    expected: '222222222222'
  },
  {
    name: 'principal organization ID alternate uses organization ID',
    request: fakeValueRequest('aws:PrincipalOrgID', 'string', 'alternate'),
    expected: 'o-otherorg'
  },
  {
    name: 'resource organization path alternate uses organization path',
    request: fakeValueRequest('aws:ResourceOrgPaths', 'string', 'alternate'),
    expected: 'o-otherorg/r-root/ou-root-sandbox/'
  },
  {
    name: 'requested region alternate uses alternate region',
    request: fakeValueRequest('aws:RequestedRegion', 'string', 'alternate'),
    expected: 'us-other-2'
  },
  {
    name: 'called via alternate uses AWS service principal',
    request: fakeValueRequest('aws:CalledVia', 'string', 'alternate'),
    expected: 'other.amazonaws.com'
  },
  {
    name: 'called via first matching fallback uses AWS service principal',
    request: fakeValueRequest('aws:CalledViaFirst', 'string', 'matchingFallback'),
    expected: 's3.amazonaws.com'
  },
  {
    name: 'principal service names list alternate uses AWS service principal',
    request: fakeValueRequest('aws:PrincipalServiceNamesList', 'string', 'alternate'),
    expected: 'other.amazonaws.com'
  },
  {
    name: 'Glue credential issuing service present value uses AWS service principal',
    request: fakeValueRequest('glue:CredentialIssuingService', 'string', 'present'),
    expected: 's3.amazonaws.com'
  },
  {
    name: 'called via AWS MCP alternate uses MCP service principal',
    request: fakeValueRequest('aws:CalledViaAWSMCP', 'string', 'alternate'),
    expected: 'other-mcp.amazonaws.com'
  },
  {
    name: 'principal type alternate uses user type',
    request: fakeValueRequest('aws:PrincipalType', 'string', 'alternate'),
    expected: 'User'
  },
  {
    name: 'userid matching fallback uses role session user id shape',
    request: fakeValueRequest('aws:userid', 'string', 'matchingFallback'),
    expected: 'AROAEXAMPLEROLEID:ExampleSession'
  },
  {
    name: 'username alternate uses person name',
    request: fakeValueRequest('aws:username', 'string', 'alternate'),
    expected: 'bob'
  },
  {
    name: 'source identity present value uses person name',
    request: fakeValueRequest('aws:SourceIdentity', 'string', 'present'),
    expected: 'alice'
  },
  {
    name: 'identitystore user ID alternate uses Identity Store user ID shape',
    request: fakeValueRequest('identitystore:UserId', 'string', 'alternate'),
    expected: 'user-22222222222222222'
  },
  {
    name: 'federated provider alternate uses external identity provider',
    request: fakeValueRequest('aws:FederatedProvider', 'string', 'alternate'),
    expected: 'accounts.google.com'
  },
  {
    name: 'referer alternate uses URL',
    request: fakeValueRequest('aws:referer', 'string', 'alternate'),
    expected: 'https://example.org/app'
  },
  {
    name: 'user agent alternate uses AWS SDK user agent',
    request: fakeValueRequest('aws:UserAgent', 'string', 'alternate'),
    expected: 'aws-sdk-js/3.x'
  },
  {
    name: 'tag keys alternate uses tag key name',
    request: fakeValueRequest('aws:TagKeys', 'string', 'alternate'),
    expected: 'Environment'
  },
  {
    name: 'principal team tag alternate uses team-like value',
    request: fakeValueRequest('aws:PrincipalTag/team', 'string', 'alternate'),
    expected: 'developer'
  },
  {
    name: 'request department tag matching fallback uses department-like value',
    request: fakeValueRequest('aws:RequestTag/Department', 'string', 'matchingFallback'),
    expected: 'engineering'
  },
  {
    name: 'resource environment tag alternate uses environment-like value',
    request: fakeValueRequest('aws:ResourceTag/Environment', 'string', 'alternate'),
    expected: 'sandbox'
  },
  {
    name: 'service-specific resource tag alternate uses generic tag value',
    request: fakeValueRequest('ec2:ResourceTag/owner', 'string', 'alternate'),
    expected: 'sandbox'
  },
  {
    name: 'service-specific request tag alternate uses generic tag value',
    request: fakeValueRequest('iam:RequestTag/project', 'string', 'alternate'),
    expected: 'sandbox'
  },
  {
    name: 'service-specific principal tag alternate uses generic tag value',
    request: fakeValueRequest('example:PrincipalTag/project', 'string', 'alternate'),
    expected: 'sandbox'
  },
  {
    name: 'unknown string key alternate uses generic string value',
    request: fakeValueRequest('custom:UnknownKey', 'string', 'alternate'),
    expected: 'other-value'
  },
  {
    name: 'unknown ARN key alternate uses generic ARN value',
    request: fakeValueRequest('custom:UnknownArnKey', 'arn', 'alternate'),
    expected: 'arn:aws:iam::222222222222:role/OtherRole'
  },
  {
    name: 'common key avoids existing preferred alternate by using second alternate',
    request: fakeValueRequest('aws:RequestedRegion', 'string', 'alternate', ['us-other-2']),
    expected: 'us-other-2-alternate'
  },
  {
    name: 'account key avoids existing preferred alternate by using second alternate',
    request: fakeValueRequest('aws:PrincipalAccount', 'string', 'alternate', ['222222222222']),
    expected: '333333333333'
  },
  {
    name: 'generic string key avoids existing preferred alternate by using second alternate',
    request: fakeValueRequest('custom:UnknownKey', 'string', 'alternate', ['other-value']),
    expected: 'alternate-value'
  }
]

interface FirstDistinctStringCase {
  name: string
  existingValues: string[]
  candidates: string[]
  expected: string
}

const firstDistinctStringCases: FirstDistinctStringCase[] = [
  {
    name: 'first candidate is available',
    existingValues: [],
    candidates: ['first', 'second'],
    expected: 'first'
  },
  {
    name: 'first candidate is already present',
    existingValues: ['first'],
    candidates: ['first', 'second'],
    expected: 'second'
  },
  {
    name: 'all candidates are already present',
    existingValues: ['first', 'second'],
    candidates: ['first', 'second'],
    expected: 'first-alternate'
  },
  {
    name: 'no candidates are provided',
    existingValues: [],
    candidates: [],
    expected: 'generated-example-value'
  }
]

describe('fakeConditionKeyValue', () => {
  for (const testCase of fakeConditionKeyValueCases) {
    it(`should return ${testCase.expected} when ${testCase.name}`, () => {
      //Given a condition-key fake value request
      const request = testCase.request

      //When a fake condition-key value is generated
      const result = fakeConditionKeyValue(request)

      //Then the generated value should match the expected deterministic example
      expect(result).toBe(testCase.expected)
    })
  }
})

describe('firstDistinctString', () => {
  for (const testCase of firstDistinctStringCases) {
    it(`should return ${testCase.expected} when ${testCase.name}`, () => {
      //Given existing values and candidate strings
      const { existingValues, candidates } = testCase

      //When a distinct string is selected
      const result = firstDistinctString(existingValues, candidates)

      //Then the expected distinct or fallback string should be returned
      expect(result).toBe(testCase.expected)
    })
  }
})

/**
 * Creates a fake condition-key value request for data-driven test cases.
 *
 * @param conditionKey - IAM condition key under test.
 * @param valueType - Truth-table value type for fallback selection.
 * @param role - Scenario role for the generated fake value.
 * @param existingValues - Optional policy values to avoid duplicating.
 * @returns Fake value request for the provided condition key.
 */
function fakeValueRequest(
  conditionKey: string,
  valueType: FakeConditionKeyValueRequest['valueType'],
  role: FakeConditionKeyValueRequest['role'],
  existingValues: string[] = []
): FakeConditionKeyValueRequest {
  return {
    conditionKey,
    valueType,
    existingValues,
    role
  }
}
