import { useState } from 'react'
import { useLocation } from 'react-router-dom'
import { HelpCircle, X } from 'lucide-react'
import { useLanguageStore } from '@/stores/languageStore'

// One small, reusable guide for every workspace route. No extra navigation,
// API permission, auth state, or "tour" workflow is created.
type Guide = { title: string; description: string }
const entries: Array<[RegExp, Guide]> = [
  [/^\/dashboard$/, { title: 'Dashboard', description: 'See the current platform status, key risks and the next action.' }],
  [/^\/projects(?:\/[^/]+)?$/, { title: 'Projects', description: 'Open a project to see its permitted assets and work.' }],
  [/^\/projects\/[^/]+\/assess$/, { title: 'New Assessment', description: 'Start an assessment in this project using its authorized scope.' }],
  [/^\/assess$/, { title: 'New Assessment', description: 'Choose a project and target. The platform verifies the permitted scope.' }],
  [/^\/assets$/, { title: 'Assets', description: 'View and manage the assets already recorded for your projects.' }],
  [/^\/web-labs$/, { title: 'Web Labs', description: 'Run controlled web lab checks using authorized test targets.' }],
  [/^\/validations\/new$/, { title: 'New Validation', description: 'Choose an existing finding, then review and start its validation.' }],
  [/^\/validations\/[^/]+\/progress$/, { title: 'Validation status', description: 'Follow progress and open results when the validation finishes.' }],
  [/^\/validations\/[^/]+\/results$/, { title: 'Security Validation Results', description: 'Review the target, findings and evidence; advanced analysis is optional.' }],
  [/^\/scan$/, { title: 'Validations', description: 'Choose a scan to view its target, status and saved results.' }],
  [/^\/scan\/[^/]+\/progress$/, { title: 'Validation status', description: 'Track the scanner progress and see which engine is running.' }],
  [/^\/scan\/[^/]+\/results$/, { title: 'Scan results', description: 'See the scanned IP or target, detected services and saved evidence.' }],
  [/^\/vulnerabilities$/, { title: 'Findings', description: 'Filter findings by severity and open one to investigate.' }],
  [/^\/vulnerabilities\/[^/]+$/, { title: 'Findings', description: 'Check the finding details, evidence and possible remediation.' }],
  [/^\/evidence$/, { title: 'Evidence', description: 'Review retained scanner proof and integrity details.' }],
  [/^\/wstg$/, { title: 'WSTG Coverage', description: 'See which web security test categories have supporting evidence.' }],
  [/^\/reports(?:\/[^/]+)?$/, { title: 'Reports', description: 'Read and export the authorized scan and validation reports.' }],
  [/^\/compliance(?:\/.*)?$/, { title: 'Compliance', description: 'Review security controls, coverage and available evidence.' }],
  [/^\/assurance\/workflow$/, { title: 'Operational Workspace', description: 'Track the existing work queue, progress and ownership.' }],
  [/^\/assurance\/actions(?:\/.*)?$/, { title: 'Decision Actions', description: 'See operational actions and their current verification status.' }],
  [/^\/assurance\/policies(?:\/.*)?$/, { title: 'Security Assurance', description: 'Inspect policies or test their effects without changing the live scope.' }],
  [/^\/assurance(?:\/.*)?$/, { title: 'Security Assurance', description: 'Review correlated security evidence, decisions and coverage.' }],
  [/^\/investigation$/, { title: 'Investigation Workspace', description: 'Follow an investigation from finding to evidence and remediation.' }],
  [/^\/posture$/, { title: 'Security Posture', description: 'See security trends and risks from available real data.' }],
  [/^\/digital-twin$/, { title: 'Digital Twin', description: 'Explore the represented assets and their recorded relationships.' }],
  [/^\/knowledge$/, { title: 'Knowledge', description: 'Find documented guidance and validated knowledge.' }],
  [/^\/executive$/, { title: 'Security Posture', description: 'View executive-level risk and assurance information.' }],
  [/^\/enterprise-security$/, { title: 'Enterprise Security', description: 'Review your organization security controls and evidence.' }],
  [/^\/users$/, { title: 'Users & RBAC', description: 'Manage permitted users and access from the existing administration UI.' }],
  [/^\/keys$/, { title: 'API Keys', description: 'Review approved API keys and their lifecycle.' }],
  [/^\/settings$/, { title: 'Settings', description: 'Manage existing settings without changing scan scope unexpectedly.' }],
  [/^\/system$/, { title: 'System Monitor', description: 'Review health, service status and operational metrics.' }],
  [/^\/security-events$/, { title: 'Security Events', description: 'Review recorded security events and their status.' }],
  [/^\/audit$/, { title: 'Audit Trail', description: 'Trace saved actions and evidence using the audit history.' }],
  [/^\/notifications$/, { title: 'Notifications', description: 'See system messages and items needing your attention.' }],
]
export const guideForRoute = (pathname: string): Guide | null =>
  entries.find(([pattern]) => pattern.test(pathname))?.[1] || null

export const PageGuide = () => {
  const { pathname } = useLocation()
  const t = useLanguageStore((state) => state.t)
  const [open, setOpen] = useState(false)
  const guide = guideForRoute(pathname)
  if (!guide) return null
  return <div className="relative">
    <button type="button" onClick={() => setOpen((value) => !value)} aria-expanded={open}
      aria-label={t('Help for this page')} title={t('Help for this page')}
      className="enterprise-icon-button rounded-xl border border-border/60 bg-background/30 p-2 transition-colors hover:bg-accent">
      <HelpCircle className="h-4 w-4" />
    </button>
    {open && <div role="dialog" aria-label={t('Page guide')} className="absolute end-0 top-full z-50 mt-3 w-[min(300px,85vw)] rounded-xl border bg-card p-4 text-start shadow-xl">
      <div className="flex items-start justify-between gap-3">
        <strong className="text-sm">{t(guide.title)}</strong>
        <button type="button" onClick={() => setOpen(false)} aria-label={t('Close')} className="rounded-md p-1 hover:bg-muted"><X className="h-4 w-4" /></button>
      </div>
      <p className="mt-2 text-sm leading-6 text-muted-foreground">{t(guide.description)}</p>
    </div>}
  </div>
}
