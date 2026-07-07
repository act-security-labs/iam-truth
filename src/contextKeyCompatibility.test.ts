import { describe, expect, it } from 'vitest'
import {
  areContextKeysCompatible,
  filterCompatibleContextKeyRows
} from './contextKeyCompatibility.js'

describe('areContextKeysCompatible', () => {
  it('should reject contexts with SourceIp and VPC network context keys together', () => {
    //Given contexts with known impossible SourceIp combinations
    const sourceVpc = { 'aws:SourceIp': '203.0.113.10', 'aws:SourceVpc': 'vpc-123' }
    const sourceVpce = { 'aws:SourceIp': '203.0.113.10', 'aws:SourceVpce': 'vpce-123' }
    const vpcSourceIp = { 'aws:SourceIp': '203.0.113.10', 'aws:VpcSourceIp': '10.0.0.1' }

    //When compatibility is checked
    const sourceVpcResult = areContextKeysCompatible(sourceVpc)
    const sourceVpceResult = areContextKeysCompatible(sourceVpce)
    const vpcSourceIpResult = areContextKeysCompatible(vpcSourceIp)

    //Then each impossible combination should be rejected
    expect(sourceVpcResult).toBe(false)
    expect(sourceVpceResult).toBe(false)
    expect(vpcSourceIpResult).toBe(false)
  })

  it('should allow each side of an exclusive pair independently', () => {
    //Given contexts where only one exclusive key is present
    const publicNetwork = { 'aws:SourceIp': '203.0.113.10' }
    const vpcNetwork = { 'aws:SourceVpc': 'vpc-123' }

    //When compatibility is checked
    const publicResult = areContextKeysCompatible(publicNetwork)
    const vpcResult = areContextKeysCompatible(vpcNetwork)

    //Then each individual context should be allowed
    expect(publicResult).toBe(true)
    expect(vpcResult).toBe(true)
  })

  it('should allow VPC endpoint context keys to coexist with each other', () => {
    //Given VPC endpoint keys without SourceIp
    const context = {
      'aws:SourceVpce': 'vpce-123',
      'aws:VpceAccount': '111111111111',
      'aws:VpceOrgID': 'o-example'
    }

    //When compatibility is checked
    const result = areContextKeysCompatible(context)

    //Then VPC endpoint keys should not be mutually exclusive with each other
    expect(result).toBe(true)
  })
})

describe('filterCompatibleContextKeyRows', () => {
  it('should remove rows with incompatible request contexts', () => {
    //Given generated rows containing compatible and incompatible contexts
    const rows = [
      { row: 'source-ip', context: { 'aws:SourceIp': '203.0.113.10' } },
      {
        row: 'both',
        context: { 'aws:SourceIp': '203.0.113.10', 'aws:SourceVpc': 'vpc-123' }
      },
      { row: 'source-vpc', context: { 'aws:SourceVpc': 'vpc-123' } }
    ]

    //When rows are filtered
    const result = filterCompatibleContextKeyRows(rows)

    //Then only compatible rows should remain
    expect(result).toEqual([
      { row: 'source-ip', context: { 'aws:SourceIp': '203.0.113.10' } },
      { row: 'source-vpc', context: { 'aws:SourceVpc': 'vpc-123' } }
    ])
  })
})
