import { describe, expect, it } from 'vitest'
import { translateExact } from './translateExact'

describe('safe browser text localization', () => {
  const ar = {
    Findings: 'الثغرات',
    'Findings Center': 'مركز الثغرات',
    'System Monitoring': 'مراقبة النظام',
    'Security Events': 'الأحداث الأمنية',
  }

  it('translates only entire known literals while retaining original whitespace', () => {
    expect(translateExact('  Findings Center  ', ar)).toBe('  مركز الثغرات  ')
    expect(translateExact('System Monitoring', ar)).toBe('مراقبة النظام')
  })

  it('does not corrupt longer words, project names, findings, or unknown dynamic data', () => {
    for (const text of [
      'Monitoring', 'Project Findings Center',
      'Findings & reports', 'Security Events API integration',
      'FindingsCenter', 'System Monitoring v2',
    ]) {
      expect(translateExact(text, ar)).toBe(text)
    }
  })

  it('does not continually translate an already translated text node', () => {
    expect(translateExact('مركز الثغرات', ar)).toBe('مركز الثغرات')
  })

  it('reverses complete literal translations for the English language', () => {
    const en = Object.fromEntries(Object.entries(ar).map(([english, arabic]) => [arabic, english]))
    expect(translateExact('مركز الثغرات', en)).toBe('Findings Center')
    expect(translateExact('الحقل: مركز الثغرات', en)).toBe('الحقل: مركز الثغرات')
  })
})
