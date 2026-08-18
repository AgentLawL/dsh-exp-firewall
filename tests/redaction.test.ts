import { describe, expect, it } from 'vitest'

import { createPreview } from '../src/redaction.ts'

describe('preview redaction', () => {
  it.each([
    ['API_KEY=abc', 'API_KEY=[REDACTED]'],
    ['myToken = "abc def"', 'myToken=[REDACTED]'],
    ["client_SECRET='abc def'", 'client_SECRET=[REDACTED]'],
    ['PASSWORD=hunter2', 'PASSWORD=[REDACTED]'],
  ])('redacts sensitive assignments: %s', (input, expected) => {
    expect(createPreview(input, 160)).toBe(expected)
  })

  it('redacts Bearer credentials case-insensitively', () => {
    expect(createPreview('Authorization: bearer abc.def', 160)).toBe('Authorization: Bearer [REDACTED]')
  })

  it('redacts URL user information while retaining the host', () => {
    expect(createPreview('curl https://alice:secret@example.com/a', 160)).toBe(
      'curl https://[REDACTED]@example.com/a',
    )
  })

  it.each([
    ['cmd --api-key value tail', 'cmd --api-key [REDACTED] tail'],
    ['cmd --TOKEN="value with space" tail', 'cmd --TOKEN [REDACTED] tail'],
    ['cmd --password secret', 'cmd --password [REDACTED]'],
  ])('redacts credential flag values: %s', (input, expected) => {
    expect(createPreview(input, 160)).toBe(expected)
  })

  it('removes consecutive ASCII controls before applying the final cap', () => {
    expect(createPreview('a\u0000\n\tb', 160)).toBe('a   b')
  })

  it('truncates by Unicode code points at exact and overlong boundaries', () => {
    expect(createPreview('甲乙丙丁', 4)).toBe('甲乙丙丁')
    expect(createPreview('甲乙丙丁戊', 4)).toBe('甲乙丙丁')
    expect([...createPreview('😀'.repeat(100), 40)]).toHaveLength(40)
  })
})
