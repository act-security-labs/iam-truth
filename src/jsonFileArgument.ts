import { singleValueArgument, type CustomArgument } from '@cloud-copilot/cli'
import { stat, readFile } from 'fs/promises'
import { type JsonPolicyDocument, type PolicyFileInput } from './types.js'

/**
 * Creates an optional CLI argument that reads and validates a JSON policy file.
 *
 * @returns A custom `@cloud-copilot/cli` argument for optional policy file input.
 */
export function policyJsonFileArgument(): CustomArgument<PolicyFileInput | undefined> {
  return singleValueArgument<PolicyFileInput>(async (path) => {
    try {
      const fileStat = await stat(path)
      if (!fileStat.isFile()) {
        return { valid: false, message: `${path} is not a file` }
      }
      const contents = await readFile(path, 'utf8')
      const parsed = parseJsonPolicyDocument(contents)
      if (!parsed) {
        return { valid: false, message: `${path} does not contain a JSON object` }
      }
      return { valid: true, value: { path, policy: parsed } }
    } catch (error: any) {
      if (error?.code === 'ENOENT') {
        return { valid: false, message: `${path} does not exist` }
      }
      return { valid: false, message: `Unable to read ${path}: ${error.message}` }
    }
  })({ description: 'A JSON policy file to read. If not provided, stdin is used.' })
}

/**
 * Parses text as a JSON object suitable for policy validation.
 *
 * @param contents - Raw JSON text to parse.
 * @returns Parsed JSON policy object, or undefined if parsing fails or does not produce an object.
 */
export function parseJsonPolicyDocument(contents: string): JsonPolicyDocument | undefined {
  try {
    const parsed = JSON.parse(contents)
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      return parsed as JsonPolicyDocument
    }
  } catch (error: any) {}
  return undefined
}
