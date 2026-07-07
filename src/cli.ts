#!/usr/bin/env node

import {
  booleanArgument,
  enumArgument,
  parseCliArguments,
  readStdin,
  stringArrayArgument,
  stringArgument
} from '@cloud-copilot/cli'
import { generateTruthTables } from './generateTruthTables.js'
import { parseJsonPolicyDocument, policyJsonFileArgument } from './jsonFileArgument.js'
import { renderTruthTablesMarkdown } from './markdown.js'

/** Runs the iam-truth CLI. */
async function run(): Promise<void> {
  const cli = await parseCliArguments(
    'iam-truth',
    {},
    {
      policyType: enumArgument({
        description: 'The type of policy to evaluate',
        validValues: ['scp', 'rcp']
      }),
      file: policyJsonFileArgument(),
      action: stringArgument({
        description:
          'Optional IAM action to simulate. Defaults to the first expanded action from the first statement.'
      }),
      resources: stringArrayArgument({
        description:
          'Optional IAM resources to simulate. Accepts one or more values and can be repeated. Defaults to *.'
      }),
      principal: stringArgument({
        description:
          'Optional principal ARN to simulate. Defaults to arn:aws:iam::111111111111:role/TestRole.'
      }),
      output: enumArgument({
        description: 'Output format to print',
        validValues: ['json', 'md'],
        defaultValue: 'json'
      }),
      showExamplesForAllPolicyValues: booleanArgument({
        description:
          'Generate one matching row for every policy value instead of one representative matching row.',
        character: 'a'
      }),
      simplify: booleanArgument({
        description: 'Simplify redundant truth-table rows into summary rows.',
        character: 's'
      })
    },
    {
      expectOperands: false
    }
  )

  if (!cli.args.policyType) {
    console.error('Missing required argument: --policy-type scp|rcp')
    cli.printHelp()
    process.exit(1)
  }

  const policy = cli.args.file?.policy ?? (await readPolicyFromStdin())
  if (!policy) {
    console.error('No JSON policy provided. Use --file or pipe a JSON policy to stdin.')
    cli.printHelp()
    process.exit(1)
  }

  const result = await generateTruthTables({
    policy,
    policyType: cli.args.policyType,
    request: {
      action: cli.args.action,
      resources: cli.args.resources,
      principal: cli.args.principal
    },
    options: {
      showExamplesForAllPolicyValues: cli.args.showExamplesForAllPolicyValues,
      simplifyTables: cli.args.simplify
    }
  })

  if (cli.args.output === 'md') {
    console.log(renderTruthTablesMarkdown(result))
  } else {
    console.log(JSON.stringify(result, null, 2))
  }
}

/**
 * Reads and parses a JSON policy document from stdin.
 *
 * @returns Parsed policy document, or undefined when stdin is empty or invalid.
 */
async function readPolicyFromStdin() {
  const stdin = await readStdin(undefined)
  if (!stdin) {
    return undefined
  }
  const policy = parseJsonPolicyDocument(stdin)
  if (!policy) {
    console.error('Invalid JSON policy provided on stdin.')
    process.exit(1)
  }
  return policy
}

run()
  .catch((error) => {
    console.error(error)
    process.exit(1)
  })
  .then(() => {})
  .finally(() => {})
