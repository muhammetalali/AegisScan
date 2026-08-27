import { Link, useLocation } from 'react-router-dom'
import { ChevronRight, Home } from 'lucide-react'
import { cn } from '@/utils/cn'

const LABELS: Record<string, string> = {
  dashboard: 'Dashboard',
  projects: 'Projects',
  assets: 'Assets',
  validations: 'Validations',
  new: 'New Validation',
  progress: 'Live Progress',
  results: 'Results',
  findings: 'Findings',
  evidence: 'Evidence',
  reports: 'Reports',
  compliance: 'Compliance',
  posture: 'Security Posture',
  'digital-twin': 'Digital Twin',
  knowledge: 'Knowledge',
  users: 'Users & RBAC',
  audit: 'Audit Trail',
  notifications: 'Notifications',
  settings: 'Settings',
  system: 'System Monitoring',
  scan: 'Scans',
  vulnerabilities: 'Vulnerabilities',
}

export const Breadcrumbs = () => {
  const location = useLocation()
  const segs = location.pathname.split('/').filter(Boolean)
  if (segs.length === 0) return null
  return (
    <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-xs">
      <Link to="/dashboard" className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground">
        <Home className="h-3.5 w-3.5" />
        <span className="hidden sm:inline">Home</span>
      </Link>
      {segs.map((s, i) => {
        const href = '/' + segs.slice(0, i + 1).join('/')
        const isLast = i === segs.length - 1
        const isId = /^[a-z]+-[a-f0-9-]+$/i.test(s) || /^[0-9]+$/.test(s)
        const label = isId ? s.slice(0, 12) : LABELS[s] || s.charAt(0).toUpperCase() + s.slice(1)
        return (
          <span key={href} className="flex items-center gap-1">
            <ChevronRight className="h-3 w-3 text-muted-foreground/60" />
            {isLast || isId ? (
              <span className={cn('truncate max-w-[120px]', isLast ? 'text-foreground font-medium' : 'text-muted-foreground')}>{label}</span>
            ) : (
              <Link to={href} className="text-muted-foreground hover:text-foreground truncate max-w-[120px]">{label}</Link>
            )}
          </span>
        )
      })}
    </nav>
  )
}
