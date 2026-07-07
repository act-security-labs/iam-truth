# @cloud-copilot/iam-truth

Generate JSON or Markdown truth tables that explain how a single AWS IAM policy behaves across representative scenarios.

## Status

Initial v1 scope supports SCP and RCP input with JSON and Markdown output.

## CLI

```sh
iam-truth --policy-type scp --file policy.json
iam-truth --policy-type rcp --file rcp.json --action s3:GetObject --resources arn:aws:s3:::example-bucket/example.txt
cat policy.json | iam-truth --policy-type scp
```

Optional request overrides:

```sh
iam-truth --policy-type scp --file policy.json --action s3:PutObject --resources '*' --principal arn:aws:iam::111111111111:role/TestRole
iam-truth --policy-type rcp --file rcp.json --action s3:GetObject --resources arn:aws:s3:::example-bucket/example.txt
```

To test the same generated scenarios against more than one resource, provide multiple `--resources` values. Multiple resources multiply the output rows and add a `Resource` column before `Result`.

```sh
iam-truth --policy-type scp --file policy.json --action s3:GetObject --resources arn:aws:s3:::example-bucket/first.txt arn:aws:s3:::example-bucket/second.txt
iam-truth --policy-type scp --file policy.json --action s3:GetObject --resources arn:aws:s3:::example-bucket/first.txt --resources arn:aws:s3:::example-bucket/second.txt
```

When simplification is enabled, the `Resource` column can collapse to `Any` when the row result is the same regardless of resource.

Resources that cannot be tested with the selected action are skipped and reported as validation diagnostics. If at least one resource is testable, iam-truth still returns rows for the testable resources and prints skipped-resource messages to stderr in the CLI.

RCP support uses generated signed requests by default, but includes missing examples for principal context keys that can be absent in resource-side/anonymous request models. RCP resource-information keys such as `aws:ResourceAccount`, `aws:ResourceOrgID`, and `aws:ResourceOrgPaths` are generated according to AWS action-specific availability.

By default, multiple policy values for a single-valued condition key produce one representative matching row. To show one matching row for every policy value:

```sh
iam-truth --policy-type scp --file policy.json --show-examples-for-all-policy-values
```

To collapse redundant rows into summary rows that use `Any` for irrelevant generated values:

```sh
iam-truth --policy-type scp --file policy.json --simplify
```

Simplified JSON rows use an object sentinel for any-value cells so real string values cannot collide with it:

```json
{ "cellType": "any", "label": "Any" }
```

Summary rows have `rowType: "summary"`, omit concrete `context`, and include `coveredRowCount` and `coveredRowIds`.

Generated request-context values are deterministic synthetic examples. User-provided policy condition values are preserved for matching rows, while non-matching and present-key examples use fake values shaped like the relevant IAM context key, such as sample account IDs, organization IDs, VPC IDs, regions, service principals, and tag values.

## API

```ts
import { generateTruthTables } from '@cloud-copilot/iam-truth'

const result = await generateTruthTables({
  policy,
  policyType: 'scp'
})

const rcpResult = await generateTruthTables({
  policy: rcpPolicy,
  policyType: 'rcp',
  request: {
    action: 's3:GetObject',
    resources: ['arn:aws:s3:::example-bucket/example.txt']
  }
})

const multiResourceResult = await generateTruthTables({
  policy,
  policyType: 'scp',
  request: {
    action: 's3:GetObject',
    resources: ['arn:aws:s3:::example-bucket/first.txt', 'arn:aws:s3:::example-bucket/second.txt']
  }
})
```

Successful JSON tables include `testedResources`, the normalized resource list used for simulation, and `untestedResources`, any requested resources that were skipped because they are not supported by the selected action. A `Resource` column is included only when more than one resource was requested.

If no requested resources can be tested for the selected action, the API returns `resultType: 'noTestableResources'` with structured `untestedResources` and diagnostics.
