import { mkdtemp, rm, writeFile, mkdir } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'
import { describe, expect, it } from 'vitest'
import { parseJsonPolicyDocument, policyJsonFileArgument } from './jsonFileArgument.js'

describe('parseJsonPolicyDocument', () => {
  it('should parse JSON objects and reject non-objects', () => {
    //Given JSON object text and JSON array text
    const objectText = '{"Statement": []}'
    const arrayText = '[]'

    //When the values are parsed as policy documents
    const objectResult = parseJsonPolicyDocument(objectText)
    const arrayResult = parseJsonPolicyDocument(arrayText)

    //Then only the object should be accepted
    expect(objectResult).toEqual({ Statement: [] })
    expect(arrayResult).toBeUndefined()
  })
})

describe('policyJsonFileArgument', () => {
  it('should validate that a file exists and contains a JSON object', async () => {
    //Given a temporary JSON policy file
    const dir = await mkdtemp(join(tmpdir(), 'iam-truth-'))
    const path = join(dir, 'policy.json')
    await writeFile(path, '{"Statement": []}')

    try {
      //When the argument validates the file path
      const argument = policyJsonFileArgument()
      const result = await argument.validateValues(undefined, [path], true)

      //Then it should return the parsed policy document
      expect(result).toEqual({ valid: true, value: { path, policy: { Statement: [] } } })
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('should reject directories and invalid JSON', async () => {
    //Given a temporary directory and invalid JSON file
    const dir = await mkdtemp(join(tmpdir(), 'iam-truth-'))
    const nestedDir = join(dir, 'nested')
    const invalidJson = join(dir, 'invalid.json')
    await mkdir(nestedDir)
    await writeFile(invalidJson, 'not json')

    try {
      //When the argument validates invalid paths
      const argument = policyJsonFileArgument()
      const directoryResult = await argument.validateValues(undefined, [nestedDir], true)
      const invalidJsonResult = await argument.validateValues(undefined, [invalidJson], true)

      //Then it should return actionable validation messages
      expect(directoryResult).toEqual({ valid: false, message: `${nestedDir} is not a file` })
      expect(invalidJsonResult).toEqual({
        valid: false,
        message: `${invalidJson} does not contain a JSON object`
      })
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})
