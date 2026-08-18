import { describe, expect, it } from 'vitest'

import { name } from '../src/index.ts'
import { pureApiVersion } from '../src/pure/index.ts'

describe('package skeleton', () => {
  it('exposes stable host and pure entry identities', () => {
    expect(name).toBe('exp-firewall')
    expect(pureApiVersion).toBe(1)
  })
})
