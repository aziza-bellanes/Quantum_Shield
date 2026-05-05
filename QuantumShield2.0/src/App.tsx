import React, { lazy, Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { ProtectedRoute } from './components/auth/ProtectedRoute'
import { AppLayout } from './components/layout/AppLayout'

// ── Lazy-loaded pages — each becomes a separate JS chunk loaded on demand ──
// This splits the ~6 MB monolithic bundle into small per-route files,
// dramatically improving First Contentful Paint on the login page.
const LoginPage             = lazy(() => import('./pages/LoginPage').then(m => ({ default: m.LoginPage })))
const SignUpPage             = lazy(() => import('./pages/SignUpPage').then(m => ({ default: m.SignUpPage })))
const GithubCallbackPage    = lazy(() => import('./pages/GithubCallbackPage').then(m => ({ default: m.GithubCallbackPage })))
const ResetPasswordPage     = lazy(() => import('./pages/ResetPasswordPage').then(m => ({ default: m.ResetPasswordPage })))
const DashboardPage         = lazy(() => import('./pages/DashboardPage').then(m => ({ default: m.DashboardPage })))
const BrowseAppsPage        = lazy(() => import('./pages/BrowseAppsPage').then(m => ({ default: m.BrowseAppsPage })))
const AccountPage           = lazy(() => import('./pages/AccountPage').then(m => ({ default: m.AccountPage })))
const ContactPage           = lazy(() => import('./pages/ContactPage').then(m => ({ default: m.ContactPage })))
const ReportsPage           = lazy(() => import('./pages/ReportsPage').then(m => ({ default: m.ReportsPage })))
const AnalyzeAppPage        = lazy(() => import('./pages/AnalyzeAppPage').then(m => ({ default: m.AnalyzeAppPage })))
const MyApplicationsPage    = lazy(() => import('./pages/MyApplicationsPage').then(m => ({ default: m.MyApplicationsPage })))
const AppReportPage         = lazy(() => import('./pages/AppReportPage').then(m => ({ default: m.AppReportPage })))
const UserManagementPage    = lazy(() => import('./pages/UserManagementPage').then(m => ({ default: m.UserManagementPage })))
const SystemMonitorPage     = lazy(() => import('./pages/SystemMonitorPage').then(m => ({ default: m.SystemMonitorPage })))
const DatabaseManagementPage = lazy(() => import('./pages/DatabaseManagementPage').then(m => ({ default: m.DatabaseManagementPage })))

// Minimal spinner shown while a page chunk is downloading
const PageLoader: React.FC = () => (
  <div className="flex min-h-[60vh] items-center justify-center">
    <span role="status" aria-label="Loading page"
      className="h-5 w-5 animate-spin rounded-full border-2 border-foreground border-t-transparent" />
  </div>
)

export const App: React.FC = () => (
  <Suspense fallback={<PageLoader />}>
    <Routes>
      <Route path="/login"                  element={<LoginPage />} />
      <Route path="/signup"                 element={<SignUpPage />} />
      <Route path="/auth/github/callback"   element={<GithubCallbackPage />} />
      <Route path="/reset-password"         element={<ResetPasswordPage />} />

      {/* Standalone report — protected, outside AppLayout for clean printing */}
      <Route element={<ProtectedRoute />}>
        <Route path="/apps/:id/report"      element={<AppReportPage />} />
      </Route>

      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard"          element={<DashboardPage />} />
          <Route path="/browse"             element={<BrowseAppsPage />} />
          <Route path="/reports"            element={<ReportsPage />} />
          <Route path="/account"            element={<AccountPage />} />
          <Route path="/contact"            element={<ContactPage />} />

          <Route element={<ProtectedRoute allowedRoles={['app_owner', 'admin']} />}>
            <Route path="/analyze"          element={<AnalyzeAppPage />} />
            <Route path="/my-apps"          element={<MyApplicationsPage />} />
          </Route>

          <Route element={<ProtectedRoute allowedRoles={['admin']} />}>
            <Route path="/users"            element={<UserManagementPage />} />
            <Route path="/system"           element={<SystemMonitorPage />} />
            <Route path="/database"         element={<DatabaseManagementPage />} />
          </Route>

          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Route>
    </Routes>
  </Suspense>
)
