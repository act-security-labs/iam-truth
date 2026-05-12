# @cloud-copilot/iam-truth

Generate JSON or Markdown truth tables that explain how a single AWS IAM policy behaves across representative scenarios.

## Status

Initial v1 scope supports SCP and RCP input with JSON and Markdown output.

## CLI

```sh
iam-truth --policy-type scp --file policy.json
iam-truth --policy-type rcp --file rcp.json --action s3:GetObject --resource arn:aws:s3:::example-bucket/example.txt
cat policy.json | iam-truth --policy-type scp
```

Optional request overrides:

```sh
iam-truth --policy-type scp --file policy.json --action s3:PutObject --resource '*' --principal arn:aws:iam::111111111111:role/TestRole
iam-truth --policy-type rcp --file rcp.json --action s3:GetObject --resource arn:aws:s3:::example-bucket/example.txt
```

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
    resource: 'arn:aws:s3:::example-bucket/example.txt'
  }
})
```
