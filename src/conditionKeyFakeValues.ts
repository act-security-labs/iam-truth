import { type TruthTableValueType } from './types.js'

/** Role a generated fake condition-key value plays in a scenario. */
export type FakeConditionKeyValueRole = 'matchingFallback' | 'alternate' | 'present'

/** Request for a deterministic synthetic value for an IAM condition key. */
export interface FakeConditionKeyValueRequest {
  /** IAM condition key that needs a generated scenario value. */
  conditionKey: string

  /** Truth-table value type resolved for the condition key. */
  valueType: TruthTableValueType

  /** Existing policy values that generated values should avoid duplicating. */
  existingValues: string[]

  /** Scenario role for the generated value. */
  role: FakeConditionKeyValueRole
}

interface FakeValueCandidates {
  matchingFallback: string[]
  alternate: string[]
  present?: string[]
}

const GENERIC_STRING_CANDIDATES: FakeValueCandidates = {
  matchingFallback: ['example-value'],
  alternate: ['other-value', 'alternate-value'],
  present: ['example-value']
}

const GENERIC_ARN_CANDIDATES: FakeValueCandidates = {
  matchingFallback: ['arn:aws:iam::111111111111:role/ExampleRole'],
  alternate: [
    'arn:aws:iam::222222222222:role/OtherRole',
    'arn:aws:iam::333333333333:role/AlternateRole'
  ],
  present: ['arn:aws:iam::111111111111:role/ExampleRole']
}

const EXACT_KEY_CANDIDATES: Record<string, FakeValueCandidates> = {
  'aws:principalarn': {
    matchingFallback: ['arn:aws:iam::111111111111:role/ExampleRole'],
    alternate: ['arn:aws:iam::222222222222:role/OtherRole'],
    present: ['arn:aws:iam::111111111111:role/ExampleRole']
  },
  'aws:sourcearn': {
    matchingFallback: ['arn:aws:s3:::example-bucket'],
    alternate: ['arn:aws:s3:::other-bucket'],
    present: ['arn:aws:s3:::example-bucket']
  },
  'aws:chatbotsourcearn': {
    matchingFallback: ['arn:aws:chatbot::111111111111:chat-configuration/slack-channel/example'],
    alternate: ['arn:aws:chatbot::222222222222:chat-configuration/slack-channel/other'],
    present: ['arn:aws:chatbot::111111111111:chat-configuration/slack-channel/example']
  },
  'ec2:sourceinstancearn': {
    matchingFallback: ['arn:aws:ec2:us-east-1:111111111111:instance/i-0123456789abcdef0'],
    alternate: ['arn:aws:ec2:us-west-2:222222222222:instance/i-0fedcba9876543210'],
    present: ['arn:aws:ec2:us-east-1:111111111111:instance/i-0123456789abcdef0']
  },
  'lambda:sourcefunctionarn': {
    matchingFallback: ['arn:aws:lambda:us-east-1:111111111111:function:example-function'],
    alternate: ['arn:aws:lambda:us-west-2:222222222222:function:other-function'],
    present: ['arn:aws:lambda:us-east-1:111111111111:function:example-function']
  },
  'ssm:sourceinstancearn': {
    matchingFallback: ['arn:aws:ssm:us-east-1:111111111111:managed-instance/mi-0123456789abcdef0'],
    alternate: ['arn:aws:ssm:us-west-2:222222222222:managed-instance/mi-0fedcba9876543210'],
    present: ['arn:aws:ssm:us-east-1:111111111111:managed-instance/mi-0123456789abcdef0']
  },
  'aws:sourcevpcarn': {
    matchingFallback: ['arn:aws:ec2:us-east-1:111111111111:vpc/vpc-0123456789abcdef0'],
    alternate: ['arn:aws:ec2:us-west-2:222222222222:vpc/vpc-0fedcba9876543210'],
    present: ['arn:aws:ec2:us-east-1:111111111111:vpc/vpc-0123456789abcdef0']
  },
  'aws:sourcevpc': vpcCandidates(),
  'aws:ec2instancesourcevpc': vpcCandidates(),
  'aws:sourcevpce': vpceCandidates(),
  'aws:vpceaccount': accountCandidates(),
  'aws:principalaccount': accountCandidates(),
  'aws:resourceaccount': accountCandidates(),
  'aws:sourceaccount': accountCandidates(),
  'aws:sourceowner': accountCandidates(),
  'aws:principalorgid': orgIdCandidates(),
  'aws:resourceorgid': orgIdCandidates(),
  'aws:sourceorgid': orgIdCandidates(),
  'aws:vpceorgid': orgIdCandidates(),
  'aws:principalorgpaths': orgPathCandidates(),
  'aws:resourceorgpaths': orgPathCandidates(),
  'aws:sourceorgpaths': orgPathCandidates(),
  'aws:vpceorgpaths': orgPathCandidates(),
  'aws:requestedregion': {
    matchingFallback: ['us-east-1'],
    alternate: ['us-other-2'],
    present: ['us-east-1']
  },
  'aws:calledvia': serviceCandidates(),
  'aws:calledviafirst': serviceCandidates(),
  'aws:calledvialast': serviceCandidates(),
  'aws:principalservicename': serviceCandidates(),
  'aws:principalservicenameslist': serviceCandidates(),
  'glue:roleassumedby': serviceCandidates(),
  'glue:credentialissuingservice': serviceCandidates(),
  'aws:calledviaawsmcp': mcpServiceCandidates(),
  'aws:principaltype': {
    matchingFallback: ['AssumedRole'],
    alternate: ['User'],
    present: ['AssumedRole']
  },
  'aws:userid': {
    matchingFallback: ['AROAEXAMPLEROLEID:ExampleSession'],
    alternate: ['AIDAEXAMPLEUSERID'],
    present: ['AROAEXAMPLEROLEID:ExampleSession']
  },
  'aws:username': userNameCandidates(),
  'aws:sourceidentity': userNameCandidates(),
  'identitystore:userid': {
    matchingFallback: ['user-11111111111111111'],
    alternate: ['user-22222222222222222'],
    present: ['user-11111111111111111']
  },
  'aws:federatedprovider': {
    matchingFallback: ['cognito-identity.amazonaws.com'],
    alternate: ['accounts.google.com'],
    present: ['cognito-identity.amazonaws.com']
  },
  'aws:referer': {
    matchingFallback: ['https://example.com/app'],
    alternate: ['https://example.org/app'],
    present: ['https://example.com/app']
  },
  'aws:useragent': {
    matchingFallback: ['aws-cli/2.15.0'],
    alternate: ['aws-sdk-js/3.x'],
    present: ['aws-cli/2.15.0']
  },
  'aws:tagkeys': {
    matchingFallback: ['Department'],
    alternate: ['Environment'],
    present: ['Department']
  }
}

/**
 * Returns a deterministic synthetic value for an IAM condition-key scenario.
 *
 * @param request - Condition-key value request describing the key, type, existing values, and role.
 * @returns Synthetic condition-key value distinct from the provided existing values when possible.
 */
export function fakeConditionKeyValue(request: FakeConditionKeyValueRequest): string {
  const candidates = candidatesForConditionKey(request.conditionKey, request.valueType)
  const roleCandidates =
    request.role === 'present'
      ? (candidates.present ?? candidates.matchingFallback)
      : candidates[request.role]
  return firstDistinctString(request.existingValues, roleCandidates)
}

/**
 * Selects a candidate string that is not already present in policy condition values.
 *
 * @param existingValues - Policy condition values to avoid duplicating.
 * @param candidates - Preferred generated values in priority order.
 * @returns The first distinct candidate, or a deterministic suffixed fallback.
 */
export function firstDistinctString(existingValues: string[], candidates: string[]): string {
  if (candidates.length === 0) {
    return 'generated-example-value'
  }

  const existing = new Set(existingValues)
  const candidate = candidates.find((value) => !existing.has(value))
  return candidate ?? `${candidates[0]}-alternate`
}

/**
 * Resolves candidate fake values for a condition key and value type.
 *
 * @param conditionKey - IAM condition key being generated.
 * @param valueType - Truth-table value type for generic fallback selection.
 * @returns Candidate fake values for the key.
 */
function candidatesForConditionKey(
  conditionKey: string,
  valueType: TruthTableValueType
): FakeValueCandidates {
  const key = conditionKey.toLowerCase()
  const exact = EXACT_KEY_CANDIDATES[key]
  if (exact) {
    return exact
  }
  if (isTagValueKey(key)) {
    return tagValueCandidates(conditionKey)
  }
  if (key.includes('orgpaths')) {
    return orgPathCandidates()
  }
  if (key.includes('orgid')) {
    return orgIdCandidates()
  }
  if (key.includes('account') || key.includes('owner')) {
    return accountCandidates()
  }
  if (valueType === 'arn') {
    return GENERIC_ARN_CANDIDATES
  }
  return GENERIC_STRING_CANDIDATES
}

/**
 * Checks whether a condition key represents a tag value rather than a tag key list.
 *
 * @param normalizedKey - Lowercase condition key to inspect.
 * @returns True when the key is a principal, request, or resource tag value key.
 */
function isTagValueKey(normalizedKey: string): boolean {
  return (
    normalizedKey.startsWith('aws:principaltag/') ||
    normalizedKey.startsWith('aws:requesttag/') ||
    normalizedKey.startsWith('aws:resourcetag/') ||
    normalizedKey.includes(':principaltag/') ||
    normalizedKey.includes(':resourcetag/') ||
    normalizedKey.includes(':requesttag/')
  )
}

/**
 * Builds tag-value candidates tuned to common tag key names when possible.
 *
 * @param conditionKey - Tag condition key including the user-provided tag key suffix.
 * @returns Candidate fake tag values.
 */
function tagValueCandidates(conditionKey: string): FakeValueCandidates {
  const tagName = conditionKey.split('/').pop()?.toLowerCase() ?? ''
  if (tagName.includes('department') || tagName === 'dept') {
    return {
      matchingFallback: ['engineering'],
      alternate: ['finance'],
      present: ['engineering']
    }
  }
  if (tagName.includes('cost')) {
    return {
      matchingFallback: ['cc-100'],
      alternate: ['cc-200'],
      present: ['cc-100']
    }
  }
  if (tagName.includes('team')) {
    return {
      matchingFallback: ['admin'],
      alternate: ['developer'],
      present: ['admin']
    }
  }
  if (tagName.includes('environment') || tagName === 'env') {
    return {
      matchingFallback: ['production'],
      alternate: ['sandbox'],
      present: ['production']
    }
  }
  return {
    matchingFallback: ['engineering'],
    alternate: ['sandbox'],
    present: ['engineering']
  }
}

/** @returns Fake AWS account ID candidates. */
function accountCandidates(): FakeValueCandidates {
  return {
    matchingFallback: ['111111111111'],
    alternate: ['222222222222', '333333333333'],
    present: ['111111111111']
  }
}

/** @returns Fake AWS Organizations ID candidates. */
function orgIdCandidates(): FakeValueCandidates {
  return {
    matchingFallback: ['o-exampleorg'],
    alternate: ['o-otherorg', 'o-alternateorg'],
    present: ['o-exampleorg']
  }
}

/** @returns Fake AWS Organizations path candidates. */
function orgPathCandidates(): FakeValueCandidates {
  return {
    matchingFallback: ['o-exampleorg/r-root/ou-root-security/'],
    alternate: ['o-otherorg/r-root/ou-root-sandbox/'],
    present: ['o-exampleorg/r-root/ou-root-security/']
  }
}

/** @returns Fake VPC ID candidates. */
function vpcCandidates(): FakeValueCandidates {
  return {
    matchingFallback: ['vpc-0123456789abcdef0'],
    alternate: ['vpc-0fedcba9876543210', 'vpc-00112233445566778'],
    present: ['vpc-0123456789abcdef0']
  }
}

/** @returns Fake VPC endpoint ID candidates. */
function vpceCandidates(): FakeValueCandidates {
  return {
    matchingFallback: ['vpce-0123456789abcdef0'],
    alternate: ['vpce-0fedcba9876543210'],
    present: ['vpce-0123456789abcdef0']
  }
}

/** @returns Fake AWS service principal candidates. */
function serviceCandidates(): FakeValueCandidates {
  return {
    matchingFallback: ['s3.amazonaws.com'],
    alternate: ['other.amazonaws.com'],
    present: ['s3.amazonaws.com']
  }
}

/** @returns Fake AWS MCP service principal candidates. */
function mcpServiceCandidates(): FakeValueCandidates {
  return {
    matchingFallback: ['iam-mcp.amazonaws.com'],
    alternate: ['other-mcp.amazonaws.com'],
    present: ['iam-mcp.amazonaws.com']
  }
}

/** @returns Fake username-like candidates. */
function userNameCandidates(): FakeValueCandidates {
  return {
    matchingFallback: ['alice'],
    alternate: ['bob'],
    present: ['alice']
  }
}
