/** Pair of condition keys that cannot both be present in the same generated request context. */
export interface ExclusiveContextKeyPair {
  /** First condition key in the exclusive pair. */
  left: string

  /** Second condition key in the exclusive pair. */
  right: string
}

const exclusiveContextKeyPairs: ExclusiveContextKeyPair[] = [
  { left: 'aws:SourceIp', right: 'aws:SourceVpc' },
  { left: 'aws:SourceIp', right: 'aws:SourceVpcArn' },
  { left: 'aws:SourceIp', right: 'aws:SourceVpce' },
  { left: 'aws:SourceIp', right: 'aws:VpceAccount' },
  { left: 'aws:SourceIp', right: 'aws:VpceOrgID' },
  { left: 'aws:SourceIp', right: 'aws:VpceOrgPaths' },
  { left: 'aws:SourceIp', right: 'aws:VpcSourceIp' }
]

/**
 * Checks whether a generated request context avoids known impossible key combinations.
 *
 * @param context - Generated request context variables.
 * @returns True when no exclusive condition-key pair is present together.
 */
export function areContextKeysCompatible(context: Record<string, unknown>): boolean {
  const presentKeys = new Set(Object.keys(context).map((key) => key.toLowerCase()))
  return exclusiveContextKeyPairs.every(
    (pair) =>
      !presentKeys.has(pair.left.toLowerCase()) || !presentKeys.has(pair.right.toLowerCase())
  )
}

/**
 * Filters generated rows to remove impossible request-context key combinations.
 *
 * @param rows - Generated rows with request context.
 * @returns Rows whose request contexts are compatible.
 */
export function filterCompatibleContextKeyRows<T extends { context: Record<string, unknown> }>(
  rows: T[]
): T[] {
  return rows.filter((row) => areContextKeysCompatible(row.context))
}
