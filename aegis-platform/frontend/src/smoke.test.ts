import { describe, expect, it } from 'vitest'

describe('frontend smoke test', () => {
  it('loads the AegisScan test runtime', () => {
    expect('AegisScan').toBe('AegisScan')
  })
})
