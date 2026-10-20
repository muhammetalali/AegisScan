// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { explainFinding } from './FindingExplanation'
describe('finding explanations are evidence-grounded', () => {
  it('does not claim a Nmap open port is a confirmed vulnerability', () => {
    const answer=explainFinding({title:'Exposed TCP port 8180 (http)',asset_target:'192.168.49.137',source_engine:'nmap',severity:'informational'})
    expect(answer.category).toBe('service_observation')
    expect(answer.where).toContain('192.168.49.137')
    expect(answer.where).toContain('8180')
    expect(answer.what).toMatch(/not proof/)
    expect(answer.how).toMatch(/separate, confirmed weakness/)
  })
  it('preserves the actual detector explanation and remediation for real findings', () => {
    const answer=explainFinding({title:'Policy weakness',description:'Recorded actual finding details',impact:'Specific verified impact',solution:'Apply actual vendor correction',asset_target:'https://lab.example/'})
    expect(answer.category).toBe('finding')
    expect(answer.what).toBe('Recorded actual finding details')
    expect(answer.how).toBe('Specific verified impact')
    expect(answer.fix).toBe('Apply actual vendor correction')
  })
  it('does not invent exploit details when no evidence is saved', () => {
    const answer=explainFinding({title:'Unknown alert'})
    expect(answer.how).toMatch(/does not establish/)
  })
})