import React, { Suspense, useEffect, useRef } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, initAuth, useAuth } from './stores/authStore'
import { ThemeProvider } from './stores/themeStore'
import { LanguageProvider, initLanguage } from './stores/languageStore'
import { RuntimeI18nBridge } from './i18n/RuntimeI18nBridge'
import { Layout } from './components/layout/Layout'
import { LoadingScreen } from './components/ui/LoadingScreen'
import { AppErrorBoundary, lazyWithRetry } from './components/ui/AppErrorBoundary'

const Login = lazyWithRetry(() => import('./pages/auth/Login').then(m => ({ default: m.Login })))
const Register = lazyWithRetry(() => import('./pages/auth/Register').then(m => ({ default: m.Register })))
const ForgotPassword = lazyWithRetry(() => import('./pages/auth/ForgotPassword').then(m => ({ default: m.ForgotPassword })))
const Dashboard = lazyWithRetry(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })))
const Projects = lazyWithRetry(() => import('./pages/projects/Projects').then(m => ({ default: m.Projects })))
const ProjectDetail = lazyWithRetry(() => import('./pages/projects/ProjectDetail').then(m => ({ default: m.ProjectDetail })))
const Assets = lazyWithRetry(() => import('./pages/assets/Assets').then(m => ({ default: m.Assets })))
const ScanPage = lazyWithRetry(() => import('./pages/scans/ScanPage').then(m => ({ default: m.ScanPage })))
const ValidationProgress = lazyWithRetry(() => import('./pages/validations/ValidationProgress').then(m => ({ default: m.ValidationProgress })))
const ValidationResults = lazyWithRetry(() => import('./pages/validations/ValidationResults').then(m => ({ default: m.ValidationResults })))
const Vulnerabilities = lazyWithRetry(() => import('./pages/vulnerabilities/Vulnerabilities').then(m => ({ default: m.Vulnerabilities })))
const VulnerabilityDetail = lazyWithRetry(() => import('./pages/vulnerabilities/VulnerabilityDetail').then(m => ({ default: m.VulnerabilityDetail })))
const Reports = lazyWithRetry(() => import('./pages/reports/Reports').then(m => ({ default: m.Reports })))
const ReportDetail = lazyWithRetry(() => import('./pages/reports/ReportDetail').then(m => ({ default: m.ReportDetail })))
const Evidence = lazyWithRetry(() => import('./pages/evidence/Evidence').then(m => ({ default: m.Evidence })))
const Compliance = lazyWithRetry(() => import('./pages/compliance/Compliance').then(m => ({ default: m.Compliance })))
const ComplianceIntelligence = lazyWithRetry(() => import('./pages/compliance/ComplianceIntelligencePage').then(m => ({ default: m.ComplianceIntelligencePage })))
const SecurityAssurance = lazyWithRetry(() => import('./pages/compliance/SecurityAssuranceCommandCenterPage').then(m => ({ default: m.SecurityAssuranceCommandCenterPage })))
const ContinuousAssurance = lazyWithRetry(() => import('./pages/assurance/ContinuousAssurancePage').then(m => ({ default: m.ContinuousAssurancePage })))
const CorrelationConflict = lazyWithRetry(() => import('./pages/compliance/CorrelationConflictPage').then(m => ({ default: m.CorrelationConflictPage })))
const CorrelatedEvidenceGraph = lazyWithRetry(() => import('./pages/compliance/CorrelatedEvidenceGraphPage').then(m => ({ default: m.CorrelatedEvidenceGraphPage })))
const AssuranceGraphPage = lazyWithRetry(() => import('./pages/assurance/AssuranceGraphPage').then(m => ({ default: m.AssuranceGraphPage })))
const AutonomousTriagePage = lazyWithRetry(() => import('./pages/assurance/AutonomousTriagePage').then(m => ({ default: m.AutonomousTriagePage })))
const SecurityDecisionPage = lazyWithRetry(() => import('./pages/assurance/SecurityDecisionPage').then(m => ({ default: m.SecurityDecisionPage })))
const DecisionActionPage = lazyWithRetry(() => import('./pages/assurance/DecisionActionPage').then(m => ({ default: m.DecisionActionPage })))
const DecisionActionDetailPage = lazyWithRetry(() => import('./pages/assurance/DecisionActionDetailPage').then(m => ({ default: m.DecisionActionDetailPage })))
const WorkflowControlTowerPage = lazyWithRetry(() => import('./pages/assurance/WorkflowControlTowerPage').then(m => ({ default: m.WorkflowControlTowerPage })))
const GovernancePage = lazyWithRetry(() => import('./pages/assurance/GovernancePage').then(m => ({ default: m.GovernancePage })))
const PolicyStudioPage = lazyWithRetry(() => import('./pages/assurance/PolicyStudioPage').then(m => ({ default: m.PolicyStudioPage })))
const PolicySimulationPage = lazyWithRetry(() => import('./pages/assurance/PolicySimulationPage').then(m => ({ default: m.PolicySimulationPage })))
const KnowledgeBase = lazyWithRetry(() => import('./pages/knowledge/KnowledgeBase').then(m => ({ default: m.KnowledgeBase })))
const DigitalTwin = lazyWithRetry(() => import('./pages/digital-twin/DigitalTwin').then(m => ({ default: m.DigitalTwin })))
const SecurityPosture = lazyWithRetry(() => import('./pages/posture/SecurityPosture').then(m => ({ default: m.SecurityPosture })))
const CISOExecutivePage = lazyWithRetry(() => import('./pages/executive/CISOExecutivePage').then(m => ({ default: m.CISOExecutivePage })))
const Users = lazyWithRetry(() => import('./pages/users/Users').then(m => ({ default: m.Users })))
const Settings = lazyWithRetry(() => import('./pages/settings/Settings').then(m => ({ default: m.Settings })))
const SystemMonitor = lazyWithRetry(() => import('./pages/system/SystemMonitor').then(m => ({ default: m.SystemMonitor })))
const AuditLogs = lazyWithRetry(() => import('./pages/audit/AuditLogs').then(m => ({ default: m.AuditLogs })))
const Notifications = lazyWithRetry(() => import('./pages/notifications/Notifications').then(m => ({ default: m.Notifications })))
const NewValidation = lazyWithRetry(() => import('./pages/validations/NewValidation').then(m => ({ default: m.NewValidation })))

const Bootstrap = ({ children }: { children: React.ReactNode }) => {
  const started = useRef(false)
  const [ready, setReady] = React.useState(false)
  useEffect(() => {
    if (started.current) return
    started.current = true
    Promise.allSettled([initLanguage(), initAuth()]).finally(() => setReady(true))
  }, [])
  if (!ready) return <LoadingScreen />
  return <>{children}</>
}

const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const { isAuthenticated, loading, initialized } = useAuth()
  if (loading || !initialized) return <LoadingScreen />
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}
const PublicRoute = ({ children }: { children: React.ReactNode }) => {
  const { isAuthenticated, loading, initialized } = useAuth()
  if (loading || !initialized) return <LoadingScreen />
  if (isAuthenticated) return <Navigate to="/dashboard" replace />
  return <>{children}</>
}
const page = (element: React.ReactNode, context: string) => <AppErrorBoundary context={context}><Suspense fallback={<LoadingScreen />}>{element}</Suspense></AppErrorBoundary>

const App = () => (
  <AppErrorBoundary context="Application shell">
    <AuthProvider>
      <ThemeProvider>
        <LanguageProvider>
          <RuntimeI18nBridge>
            <Bootstrap>
              <Routes>
                <Route path="/login" element={<PublicRoute>{page(<Login />, 'Login')}</PublicRoute>} />
                <Route path="/register" element={<PublicRoute>{page(<Register />, 'Registration')}</PublicRoute>} />
                <Route path="/forgot-password" element={<PublicRoute>{page(<ForgotPassword />, 'Password recovery')}</PublicRoute>} />
                <Route element={<ProtectedRoute><AppErrorBoundary context="Workspace shell"><Layout /></AppErrorBoundary></ProtectedRoute>}>
                  <Route path="/dashboard" element={page(<Dashboard />, 'Dashboard')} />
                  <Route path="/projects" element={page(<Projects />, 'Projects')} />
                  <Route path="/projects/:id" element={page(<ProjectDetail />, 'Project detail')} />
                  <Route path="/assets" element={page(<Assets />, 'Assets')} />
                  <Route path="/validations/new" element={page(<NewValidation />, 'New validation')} />
                  <Route path="/validations/:id/progress" element={page(<ValidationProgress />, 'Validation progress')} />
                  <Route path="/validations/:id/results" element={page(<ValidationResults />, 'Validation results')} />
                  <Route path="/scan" element={page(<ScanPage />, 'Scans')} />
                  <Route path="/scan/:id/progress" element={page(<ValidationProgress />, 'Scan progress')} />
                  <Route path="/scan/:id/results" element={page(<ValidationResults />, 'Scan results')} />
                  <Route path="/vulnerabilities" element={page(<Vulnerabilities />, 'Vulnerabilities')} />
                  <Route path="/vulnerabilities/:id" element={page(<VulnerabilityDetail />, 'Vulnerability detail')} />
                  <Route path="/evidence" element={page(<Evidence />, 'Evidence')} />
                  <Route path="/reports" element={page(<Reports />, 'Reports')} />
                  <Route path="/reports/:id" element={page(<ReportDetail />, 'Report detail')} />
                  <Route path="/compliance" element={page(<Compliance />, 'Compliance')} />
                  <Route path="/compliance/intelligence" element={page(<ComplianceIntelligence />, 'Compliance intelligence')} />
                  <Route path="/assurance" element={page(<SecurityAssurance />, 'Security assurance')} />
                  <Route path="/assurance/continuous" element={page(<ContinuousAssurance />, 'Continuous assurance')} />
                  <Route path="/assurance/conflicts" element={page(<CorrelationConflict />, 'Correlation conflicts')} />
                  <Route path="/assurance/evidence" element={page(<CorrelatedEvidenceGraph />, 'Correlated evidence')} />
                  <Route path="/assurance/graph" element={page(<AssuranceGraphPage />, 'Assurance graph')} />
                  <Route path="/assurance/triage" element={page(<AutonomousTriagePage />, 'Autonomous triage')} />
                  <Route path="/assurance/decisions" element={page(<SecurityDecisionPage />, 'Security decisions')} />
                  <Route path="/assurance/actions" element={page(<DecisionActionPage />, 'Decision actions')} />
                  <Route path="/assurance/actions/:actionId" element={page(<DecisionActionDetailPage />, 'Decision action detail')} />
                  <Route path="/assurance/workflow" element={page(<WorkflowControlTowerPage />, 'Workflow control tower')} />
                  <Route path="/assurance/governance" element={page(<GovernancePage />, 'Governance')} />
                  <Route path="/assurance/policies" element={page(<PolicyStudioPage />, 'Policy studio')} />
                  <Route path="/assurance/policies/simulate" element={page(<PolicySimulationPage />, 'Policy simulation')} />
                  <Route path="/knowledge" element={page(<KnowledgeBase />, 'Knowledge base')} />
                  <Route path="/digital-twin" element={page(<DigitalTwin />, 'Digital twin')} />
                  <Route path="/posture" element={page(<SecurityPosture />, 'Security posture')} />
                  <Route path="/executive" element={page(<CISOExecutivePage />, 'CISO executive')} />
                  <Route path="/users" element={page(<Users />, 'Users and RBAC')} />
                  <Route path="/settings" element={page(<Settings />, 'Settings')} />
                  <Route path="/system" element={page(<SystemMonitor />, 'System monitor')} />
                  <Route path="/audit" element={page(<AuditLogs />, 'Audit trail')} />
                  <Route path="/notifications" element={page(<Notifications />, 'Notifications')} />
                  <Route path="/" element={<Navigate to="/dashboard" replace />} />
                </Route>
                <Route path="*" element={<Navigate to="/dashboard" replace />} />
              </Routes>
            </Bootstrap>
          </RuntimeI18nBridge>
        </LanguageProvider>
      </ThemeProvider>
    </AuthProvider>
  </AppErrorBoundary>
)
export default App
