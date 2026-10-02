import { Center, Loader, Stack, Text } from '@mantine/core'
import { useEffect } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'

import { AppLayout } from './components/AppLayout'
import { useAuth } from './lib/auth'
import { LoginPage } from './pages/Login'
import { NotFoundPage } from './pages/NotFound'
import { OverviewPage } from './pages/Overview'
import { MyAiPage } from './pages/MyAi'
import { MyApprovalsPage } from './pages/MyApprovals'
import { MyAuditPage } from './pages/MyAudit'
import { MyBitbucketPage } from './pages/MyBitbucket'
import { MyKeysPage } from './pages/MyKeys'
import { MyPermissionsPage } from './pages/MyPermissions'
import { MySettingsPage } from './pages/MySettings'
import { MyToolsPage } from './pages/MyTools'
import { AdminDashboardPage } from './pages/admin/Dashboard'
import { AdminAiPage } from './pages/admin/Ai'
import { AdminApprovalsPage } from './pages/admin/Approvals'
import { AdminAuditPage } from './pages/admin/Audit'
import { AdminAuthPage } from './pages/admin/Auth'
import { AdminBitbucketPage } from './pages/admin/Bitbucket'
import { AdminIdentityPage } from './pages/admin/Identity'
import { AdminKeysPage } from './pages/admin/Keys'
import { AdminPermissionPage } from './pages/admin/Permission'
import { AdminPolicyPage } from './pages/admin/Policy'
import { AdminSecurityPage } from './pages/admin/Security'
import { AdminSessionsPage } from './pages/admin/Sessions'
import { AdminSystemPage } from './pages/admin/System'
import { AdminToolsPage } from './pages/admin/Tools'
import { AdminUiPage } from './pages/admin/Ui'
import { AdminUsersPage } from './pages/admin/Users'

function FullScreenLoader({ label }: { label: string }) {
  return (
    <Center h="100vh">
      <Stack align="center" gap="sm">
        <Loader size="lg" />
        <Text c="dimmed">{label}</Text>
      </Stack>
    </Center>
  )
}

/** RequireAuth keeps the attempted path so a refresh returns to the same screen. */
function RequireAuth({ children }: { children: React.ReactNode }) {
  const { me, loading } = useAuth()
  const location = useLocation()

  if (loading) return <FullScreenLoader label="세션을 확인하고 있습니다…" />
  if (!me) {
    const target = `${location.pathname}${location.search}`
    return <Navigate to={`/login?returnTo=${encodeURIComponent(target)}`} replace />
  }
  return <>{children}</>
}

function RequireAdmin({ children }: { children: React.ReactNode }) {
  const { me } = useAuth()
  if (me && !me.isServiceAdmin) return <Navigate to="/" replace />
  return <>{children}</>
}

export function App() {
  const { me, loading } = useAuth()

  // Apply the user's font scale and theme preference to the document.
  useEffect(() => {
    const scale = me?.prefs.fontScale ?? me?.ui.fontScale ?? 1
    document.documentElement.style.setProperty('--bbmcp-font-scale', String(scale))
  }, [me?.prefs.fontScale, me?.ui.fontScale])

  useEffect(() => {
    const name = me?.ui.serviceName ?? 'bbmcp'
    document.title = `${name} — ${me?.ui.tagline ?? 'Bitbucket MCP 게이트웨이'}`
  }, [me?.ui.serviceName, me?.ui.tagline])

  if (loading) return <FullScreenLoader label="서비스를 준비하고 있습니다…" />

  return (
    <Routes>
      <Route path="/login" element={me ? <Navigate to="/" replace /> : <LoginPage />} />

      <Route
        element={
          <RequireAuth>
            <AppLayout />
          </RequireAuth>
        }
      >
        <Route path="/" element={<OverviewPage />} />
        <Route path="/me/keys" element={<MyKeysPage />} />
        <Route path="/me/bitbucket" element={<MyBitbucketPage />} />
        <Route path="/me/approvals" element={<MyApprovalsPage />} />
        <Route path="/me/tools" element={<MyToolsPage />} />
        <Route path="/me/permissions" element={<MyPermissionsPage />} />
        <Route path="/me/ai" element={<MyAiPage />} />
        <Route path="/me/audit" element={<MyAuditPage />} />
        <Route path="/me/settings" element={<MySettingsPage />} />

        <Route
          path="/admin"
          element={
            <RequireAdmin>
              <AdminDashboardPage />
            </RequireAdmin>
          }
        />
        <Route
          path="/admin/*"
          element={
            <RequireAdmin>
              <Routes>
                <Route path="auth" element={<AdminAuthPage />} />
                <Route path="bitbucket" element={<AdminBitbucketPage />} />
                <Route path="permission" element={<AdminPermissionPage />} />
                <Route path="identity" element={<AdminIdentityPage />} />
                <Route path="tools" element={<AdminToolsPage />} />
                <Route path="policy" element={<AdminPolicyPage />} />
                <Route path="approvals" element={<AdminApprovalsPage />} />
                <Route path="sessions" element={<AdminSessionsPage />} />
                <Route path="keys" element={<AdminKeysPage />} />
                <Route path="users" element={<AdminUsersPage />} />
                <Route path="ai" element={<AdminAiPage />} />
                <Route path="security" element={<AdminSecurityPage />} />
                <Route path="ui" element={<AdminUiPage />} />
                <Route path="audit" element={<AdminAuditPage />} />
                <Route path="system" element={<AdminSystemPage />} />
                <Route path="*" element={<NotFoundPage />} />
              </Routes>
            </RequireAdmin>
          }
        />

        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
