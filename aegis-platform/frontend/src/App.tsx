import React, { Suspense, lazy } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './stores/authStore'
import { ThemeProvider } from './stores/themeStore'
import { LanguageProvider } from './stores/languageStore'
import { Layout } from './components/layout/Layout'
import { LoadingScreen } from './components/ui/LoadingScreen'

const Login = lazy(() => import('./pages/auth/Login').then(m => ({ default: m.Login })))
const Register = lazy(() => import('./pages/auth/Register').then(m => ({ default: m.Register })))
const ForgotPassword = lazy(() => import('./pages/auth/ForgotPassword').then(m => ({ default: m.ForgotPassword })))
const Dashboard = lazy(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })))
const Projects = lazy(() => import('./pages/projects/Projects').then(m => ({ default: m.Projects })))
const ProjectDetail = lazy(() => import('./pages/projects/ProjectDetail').then(m => ({ default: m.ProjectDetail })))
const Assets = lazy(() => import('./pages/assets/Assets').then(m => ({ default: m.Assets })))
const ScanPage = lazy(() => import('./pages/scans/ScanPage').then(m => ({ default: m.ScanPage })))
const ScanProgress = lazy(() => import('./pages/scans/ScanProgress').then(m => ({ default: m.ScanProgress })))
const ScanResults = lazy(() => import('./pages/validations/ValidationCommandCenter').then(m => ({ default: m.ValidationCommandCenter })))
const Vulnerabilities = lazy(() => import('./pages/vulnerabilities/Vulnerabilities').then(m => ({ default: m.Vulnerabilities })))
const VulnerabilityDetail = lazy(() => import('./pages/vulnerabilities/VulnerabilityDetail').then(m => ({ default: m.VulnerabilityDetail })))
const Reports = lazy(() => import('./pages/reports/Reports').then(m => ({ default: m.Reports })))
const ReportDetail = lazy(() => import('./pages/reports/ReportDetail').then(m => ({ default: m.ReportDetail })))
const Compliance = lazy(() => import('./pages/compliance/Compliance').then(m => ({ default: m.Compliance })))
const ComplianceIntelligence = lazy(() => import('./pages/compliance/ComplianceIntelligencePage').then(m => ({ default: m.ComplianceIntelligencePage })))
const SecurityAssurance = lazy(() => import('./pages/compliance/SecurityAssuranceCommandCenterPage').then(m => ({ default: m.SecurityAssuranceCommandCenterPage })))
const ContinuousAssurance = lazy(() => import('./pages/assurance/ContinuousAssurancePage').then(m => ({ default: m.ContinuousAssurancePage })))
const CorrelationConflict = lazy(() => import('./pages/compliance/CorrelationConflictPage').then(m => ({ default: m.CorrelationConflictPage })))
const CorrelatedEvidenceGraph = lazy(() => import('./pages/compliance/CorrelatedEvidenceGraphPage').then(m => ({ default: m.CorrelatedEvidenceGraphPage })))
const AssuranceGraphPage = lazy(() => import('./pages/assurance/AssuranceGraphPage').then(m => ({ default: m.AssuranceGraphPage })))
const AutonomousTriagePage = lazy(() => import('./pages/assurance/AutonomousTriagePage').then(m => ({ default: m.AutonomousTriagePage })))
const SecurityDecisionPage = lazy(() => import('./pages/assurance/SecurityDecisionPage').then(m => ({ default: m.SecurityDecisionPage })))
const DecisionActionPage = lazy(() => import('./pages/assurance/DecisionActionPage').then(m => ({ default: m.DecisionActionPage })))
const DecisionActionDetailPage = lazy(() => import('./pages/assurance/DecisionActionDetailPage').then(m => ({ default: m.DecisionActionDetailPage })))
const WorkflowControlTowerPage = lazy(() => import('./pages/assurance/WorkflowControlTowerPage').then(m => ({ default: m.WorkflowControlTowerPage })))
const GovernancePage = lazy(() => import('./pages/assurance/GovernancePage').then(m => ({ default: m.GovernancePage })))
const PolicyStudioPage = lazy(() => import('./pages/assurance/PolicyStudioPage').then(m => ({ default: m.PolicyStudioPage })))
const PolicySimulationPage = lazy(() => import('./pages/assurance/PolicySimulationPage').then(m => ({ default: m.PolicySimulationPage })))
const KnowledgeBase = lazy(() => import('./pages/knowledge/KnowledgeBase').then(m => ({ default: m.KnowledgeBase })))
const DigitalTwin = lazy(() => import('./pages/digital-twin/DigitalTwin').then(m => ({ default: m.DigitalTwin })))
const SecurityPosture = lazy(() => import('./pages/posture/SecurityPosture').then(m => ({ default: m.SecurityPosture })))
const CISOExecutivePage = lazy(() => import('./pages/executive/CISOExecutivePage').then(m => ({ default: m.CISOExecutivePage })))
const Users = lazy(() => import('./pages/users/Users').then(m => ({ default: m.Users })))
const Settings = lazy(() => import('./pages/settings/Settings').then(m => ({ default: m.Settings })))
const SystemMonitor = lazy(() => import('./pages/system/SystemMonitor').then(m => ({ default: m.SystemMonitor })))
const AuditLogs = lazy(() => import('./pages/audit/AuditLogs').then(m => ({ default: m.AuditLogs })))
const Notifications = lazy(() => import('./pages/notifications/Notifications').then(m => ({ default: m.Notifications })))
const NewValidation = lazy(() => import('./pages/validations/ValidationWizard').then(m => ({ default: m.ValidationWizard })))

const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const { isAuthenticated, loading } = useAuth()
  if (loading) return <LoadingScreen />
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

const PublicRoute = ({ children }: { children: React.ReactNode }) => {
  const { isAuthenticated, loading } = useAuth()
  if (loading) return <LoadingScreen />
  if (isAuthenticated) return <Navigate to="/dashboard" replace />
  return <>{children}</>
}

const page = (element: React.ReactNode) => <Suspense fallback={<LoadingScreen />}>{element}</Suspense>

const App = () => (
  <AuthProvider>
    <ThemeProvider>
      <LanguageProvider>
        <Routes>
          <Route path="/login" element={<PublicRoute>{page(<Login />)}</PublicRoute>} />
          <Route path="/register" element={<PublicRoute>{page(<Register />)}</PublicRoute>} />
          <Route path="/forgot-password" element={<PublicRoute>{page(<ForgotPassword />)}</PublicRoute>} />
          <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
            <Route path="/dashboard" element={page(<Dashboard />)} />
            <Route path="/projects" element={page(<Projects />)} />
            <Route path="/projects/:id" element={page(<ProjectDetail />)} />
            <Route path="/assets" element={page(<Assets />)} />
            <Route path="/validations/new" element={page(<NewValidation />)} />
            <Route path="/validations/:id/progress" element={page(<ScanProgress />)} />
            <Route path="/validations/:id/results" element={page(<ScanResults />)} />
            <Route path="/scan" element={page(<ScanPage />)} />
            <Route path="/scan/:id/progress" element={page(<ScanProgress />)} />
            <Route path="/scan/:id/results" element={page(<ScanResults />)} />
            <Route path="/vulnerabilities" element={page(<Vulnerabilities />)} />
            <Route path="/vulnerabilities/:id" element={page(<VulnerabilityDetail />)} />
            <Route path="/reports" element={page(<Reports />)} />
            <Route path="/reports/:id" element={page(<ReportDetail />)} />
            <Route path="/compliance" element={page(<Compliance />)} />
            <Route path="/compliance/intelligence" element={page(<ComplianceIntelligence />)} />
            <Route path="/assurance" element={page(<SecurityAssurance />)} />
            <Route path="/assurance/continuous" element={page(<ContinuousAssurance />)} />
            <Route path="/assurance/conflicts" element={page(<CorrelationConflict />)} />
            <Route path="/assurance/evidence" element={page(<CorrelatedEvidenceGraph />)} />
            <Route path="/assurance/graph" element={page(<AssuranceGraphPage />)} />
            <Route path="/assurance/triage" element={page(<AutonomousTriagePage />)} />
            <Route path="/assurance/decisions" element={page(<SecurityDecisionPage />)} />
            <Route path="/assurance/actions" element={page(<DecisionActionPage />)} />
            <Route path="/assurance/actions/:actionId" element={page(<DecisionActionDetailPage />)} />
            <Route path="/assurance/workflow" element={page(<WorkflowControlTowerPage />)} />
            <Route path="/assurance/governance" element={page(<GovernancePage />)} />
            <Route path="/assurance/policies" element={page(<PolicyStudioPage />)} />
            <Route path="/assurance/policies/simulate" element={page(<PolicySimulationPage />)} />
            <Route path="/knowledge" element={page(<KnowledgeBase />)} />
            <Route path="/digital-twin" element={page(<DigitalTwin />)} />
            <Route path="/posture" element={page(<SecurityPosture />)} />
            <Route path="/executive" element={page(<CISOExecutivePage />)} />
            <Route path="/users" element={page(<Users />)} />
            <Route path="/settings" element={page(<Settings />)} />
            <Route path="/system" element={page(<SystemMonitor />)} />
            <Route path="/audit" element={page(<AuditLogs />)} />
            <Route path="/notifications" element={page(<Notifications />)} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
          </Route>
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </LanguageProvider>
    </ThemeProvider>
  </AuthProvider>
)

export default App
