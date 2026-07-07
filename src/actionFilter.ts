import { actionMatchesPattern } from '@cloud-copilot/iam-expand'
import { type Statement } from '@cloud-copilot/iam-policy'

/**
 * Filters policy statements to those whose Action or NotAction element can apply to a tested action.
 *
 * @param statements - Policy statements to filter.
 * @param testedAction - Concrete IAM action being tested.
 * @returns Statements whose action scope includes the tested action.
 */
export function statementsApplicableToAction(
  statements: Statement[],
  testedAction: string
): Statement[] {
  return statements.filter((statement) => statementAppliesToAction(statement, testedAction))
}

/**
 * Checks whether one statement can apply to the tested action.
 *
 * @param statement - Policy statement to inspect.
 * @param testedAction - Concrete IAM action being tested.
 * @returns True when the statement action scope includes the tested action.
 */
export function statementAppliesToAction(statement: Statement, testedAction: string): boolean {
  if (statement.isActionStatement()) {
    return statement.actions().some((action) => actionPatternMatches(testedAction, action.value()))
  }
  if (statement.isNotActionStatement()) {
    return !statement
      .notActions()
      .some((action) => actionPatternMatches(testedAction, action.value()))
  }
  return false
}

/**
 * Checks whether a policy action pattern matches a tested action.
 *
 * @param testedAction - Concrete IAM action being tested.
 * @param pattern - Action pattern from the policy.
 * @returns True when the pattern matches the action.
 */
function actionPatternMatches(testedAction: string, pattern: string): boolean {
  if (/^\*+$/i.test(pattern)) {
    return true
  }
  return actionMatchesPattern(testedAction, pattern)
}
