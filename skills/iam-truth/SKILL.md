---
name: iam-truth
description: Build a truth table showing under which conditions an AWS SCP or RCP denies or does not deny a request, by running iam-truth through npx with nothing installed. Use for "when does this SCP or RCP block X" questions and for reviewing guardrail policies; SCP and RCP only, not identity or resource policies.
license: MIT
compatibility: Node.js 22 or newer with npx; network access to registry.npmjs.org on first run.
metadata:
  author: act-security
  version: "0.1.0"
---

[iam-truth](https://github.com/act-security-labs/iam-truth) generates a truth table for one SCP or RCP: synthetic request scenarios across the policy's condition values, each row showing whether the policy denies. Input from stdin or `--file`; `--policy-type scp|rcp` is required.

## Run

```bash
cat scp.json | npx -y @actsecurity/iam-truth@latest --policy-type scp --action ec2:RunInstances --output md
npx -y @actsecurity/iam-truth@latest --policy-type rcp --file rcp.json --action s3:GetObject --resources arn:aws:s3:::bucket/key --output md
```

Point it at the user's question. The defaults answer a generic one: action is the first expanded action of the first statement, resource is `*`, principal is a test role.

- `--action`: the request being evaluated.
- `--resources` (repeatable): each extra resource multiplies the rows; `--simplify` collapses to `Any` where the resource does not change the outcome.
- `--principal`: matters for RCPs and for conditions on principal keys.

`--help` is the authoritative flag list. Only what it does not say is below.

## What `--help` does not say

- **SCPs and RCPs only.** An identity, resource, or trust policy is out of scope; say so instead of forcing it through as an SCP.
- **`--output md` is for the user, `json` for you.** Show the Markdown table exactly as printed, then interpret below it; a table you rewrite or merge from several runs is no longer the tool's evidence.
- **Rows are synthetic examples.** The tool takes condition values from the policy and generates matching and non-matching values (sample account IDs, org IDs, regions such as `us-other-2`). A row does not claim that request exists in the user's account, and there is no flag to pin a request context key such as a specific region.
- **`resultType` is the answer even when it is not `success`.** `invalidPolicy`, `unsupportedConditionKeys`, `tooManyRows`, `noTestableResources` and the rest carry `diagnostics[]` with `code`, `message`, and often `path` or `conditionKey`. Relay them; they say what the tool cannot model.
- **Row explosion.** Scenarios are the Cartesian product of condition values across keys, times resources. On `tooManyRows` or an unreadable table, narrow with `--action` and fewer `--resources`, then `--simplify`. `-a` gives one row per policy value instead of one representative row.
- **Skipped resources go to stderr** with a `RESOURCE_UNSUPPORTED_FOR_ACTION` diagnostic; capture stderr and mention them.
- **Stale catalog.** `iam-truth` has no `--show-data-version`; if freshness matters, ask `npx -y @actsecurity/iam-expand@latest --show-data-version`, and refresh with `npx -y -p @actsecurity/iam-data@latest -p @actsecurity/iam-truth@latest iam-truth`.

## Reading a row

Markdown labels are `Denied`, `Not Denied`, `Allowed`, `Implicitly Denied`; JSON carries `explicitlyDenied`, `notDenied`, `allowed`, `implicitlyDenied`.

| Label | Meaning |
|---|---|
| `Denied` | This policy denies the request in that scenario |
| `Not Denied` | This policy does not block it. For a deny-only SCP this is the common "passes the guardrail" row and says nothing about whether an identity policy allows the request |
| `Allowed` | An allow-list SCP or RCP matches |
| `Implicitly Denied` | No statement matches in an allow-list policy |

A table with no condition columns means the action never meets a conditioned statement, usually because it sits in a `NotAction` list or an unconditioned Deny covers it.

## Present

The table as printed, then your reading in its own section, labeled as yours, always stating that `Not Denied` is not `Allowed`.
