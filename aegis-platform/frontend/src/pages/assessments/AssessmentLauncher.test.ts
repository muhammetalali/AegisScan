import { describe, expect, it } from 'vitest'
import { detectAssessmentTargetMode } from './AssessmentLauncher'

describe('canonical assessment entry detects URL, DNS, IP and CIDR without a separate API', () => {
  it.each([
    ['192.168.49.10', 'ip'],
    ['2001:db8::1', 'ip'],
    ['192.168.49.33/24', 'network'],
    ['2001:db8::/64', 'network'],
    ['example.com', 'url'],
    ['internal.example/app', 'url'],
    ['https://app.example.com/login', 'url'],
    ['http://[::1]:8080', 'url'],
    ['localhost:8000', 'url'],
  ] as const)('classifies %s as %s for the existing backend mode', (input, expected) => {
    expect(detectAssessmentTargetMode(input)).toBe(expected)
  })

  it('does not guess a mode for empty or incomplete numeric input', () => {
    expect(detectAssessmentTargetMode('')).toBeNull()
    expect(detectAssessmentTargetMode('  ')).toBeNull()
    expect(detectAssessmentTargetMode('192.168.')).toBeNull()
  })

  it('lets server-side normalization reject invalid URLs and numeric ranges', () => {
    // The browser only selects an existing API mode; it never grants target scope.
    expect(detectAssessmentTargetMode('999.999.999.999')).toBe('ip')
    expect(detectAssessmentTargetMode('ftp://example.com')).toBe('url')
  })
})
