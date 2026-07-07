# iam-truth Scenario Tests

This directory contains JSON-driven end-to-end tests for the public `generateTruthTables` API.

The test runner is:

```text
../scenarioTests.test.ts
```

It recursively reads every `.json` file under this directory, so fixtures can be organized in subfolders.

## Organization

```text
scenario-tests/
  effect-action/
    deny-only.json
    allow-only.json
    allow-and-deny.json
  global-condition-keys/
    principal.json
    session.json
    network.json
    resource.json
    request.json
  rcp/
    basic.json
    principal-context.json
```

- `effect-action/` covers combinations of policy effect mode and `Action` / `NotAction` shape.
- `global-condition-keys/` covers global condition keys grouped by IAM condition-key category.
- `rcp/` covers Resource Control Policy support and RCP-specific request-context behavior.

## File Format

Each file has a description and a list of cases:

```json
{
  "description": "Effect/action matrix: allow-and-deny",
  "cases": [
    {
      "name": "allow and deny with Action succeeds",
      "input": {
        "policyType": "scp",
        "policy": {},
        "request": {
          "resources": ["*"]
        }
      },
      "expected": {}
    }
  ]
}
```

Each case is run independently. Optional case flags:

- `skip: true` skips the case.
- `only: true` focuses the case with `it.only`.

## Preferred Success Expectation Format

For successful truth-table cases, prefer the compact table format:

```json
"expected": {
  "resultType": "success",
  "table": {
    "effectMode": "allowAndDeny",
    "columns": [
      {
        "key": "aws:ResourceOrgID",
        "label": "Organization ID",
        "valueType": "string"
      },
      {
        "key": "aws:ViaAWSService",
        "label": "Is Via Service?",
        "valueType": "boolean"
      },
      {
        "key": "result",
        "label": "Result",
        "valueType": "result"
      }
    ],
    "rows": [
      ["o-example", false, "explicitlyDenied"],
      ["o-example", true, "allowed"],
      ["o-otherorg", false, "explicitlyDenied"],
      ["o-otherorg", true, "implicitlyDenied"],
      [null, false, "explicitlyDenied"],
      [null, true, "allowed"]
    ]
  }
}
```

### Compact Row Rules

- `columns` defines the positional meaning of each value in `rows`.
- Each compact row corresponds to one generated truth-table row.
- The row id is implied by position and verified by the harness:
  - first row => `row-1`
  - second row => `row-2`
  - etc.
- For normal condition-key columns, row values are compared to `row.cells[column.key]`.
- For the `result` column, row values are compared to `row.result.resultType`.

Use `testedResources` in the expected table when a case needs to assert the normalized resource list used for simulation.

Use result types rather than labels in compact rows:

- `allowed`
- `implicitlyDenied`
- `explicitlyDenied`
- `notDenied`

Use `null` for missing condition-key cells. Use JSON arrays for multivalue condition-key cells, for example `["o-example/r-root/", "o-other/r-root/"]`.

Use `{ "cellType": "any", "label": "Any" }` for simplified summary cells that represent any generated value for the column. When asserting simplified tables, include the table `simplification` metadata if the source and simplified row counts matter.

## Exact Result Format

Use `exactResult` when the full result shape is important, especially for invalid/error cases and diagnostics-heavy cases:

```json
"expected": {
  "exactResult": {
    "resultType": "invalidPolicy",
    "diagnostics": [
      {
        "severity": "error",
        "code": "INVALID_POLICY",
        "message": "Only one of Action or NotAction is allowed, found both",
        "path": "Statement[0]",
        "policyType": "scp"
      }
    ]
  }
}
```

## Partial Assertion Format

The harness still supports partial assertions when a fixture needs flexibility:

```json
"expected": {
  "resultType": "success",
  "table": {
    "effectMode": "denyOnly",
    "includesColumnKeys": ["aws:ResourceOrgID", "result"],
    "includesRowResults": ["Denied", "Not Denied"],
    "rowsInclude": [
      {
        "cells": {
          "aws:ResourceOrgID": "o-example",
          "result": "Denied"
        },
        "result": {
          "label": "Denied"
        }
      }
    ]
  }
}
```

Prefer compact rows for end-to-end success cases because they are easier to review and still assert every generated scenario.

## Adding New Cases

When adding a case:

1. Put it in the most specific subfolder.
2. Prefer compact success expectations.
3. Include every generated scenario row in order.
4. Use `exactResult` for invalid/error results.
5. Keep the policy input minimal so the expected rows are easy to understand.
6. Run:

```sh
npm run build
npm test
npm run format-check
```
