import { lazy } from 'react';
import { Navigate, Route, Routes, useParams } from 'react-router-dom';

import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { AppShell } from '@/components/layout/AppShell';
import { LoginPage } from '@/pages/LoginPage';

// Load authenticated pages on demand, including the dashboard chart library.
const DashboardPage = lazy(() => import('@/pages/DashboardPage').then((m) => ({ default: m.DashboardPage })));
const InboxPage = lazy(() => import('@/pages/InboxPage').then((m) => ({ default: m.InboxPage })));
const SenderListsPage = lazy(() => import('@/pages/SenderListsPage').then((m) => ({ default: m.SenderListsPage })));
const SettingsPage = lazy(() => import('@/pages/SettingsPage').then((m) => ({ default: m.SettingsPage })));

/*
  Old /inbox/:emailId links carried the message in the PATH. The inbox now keeps
  the open message in `?selected=`, so this redirect has to translate between the
  two — a bare <Navigate to="/inbox"> would drop the id and land the user on
  whatever happens to be first in the list, which is what it used to do.
*/
function InboxMessageRedirect() {
  const { emailId } = useParams();
  return <Navigate to={emailId ? `/inbox?selected=${encodeURIComponent(emailId)}` : '/inbox'} replace />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />

      <Route
        element={
          <ProtectedRoute>
            <AppShell />
          </ProtectedRoute>
        }
      >
        <Route path="/dashboard" element={<DashboardPage />} />
        {/* /inbox/:emailId used to render a separate full-page report in the
            old design. The inbox is now a two-pane workspace where the reading
            pane holds everything, so the route redirects instead of showing a
            second, differently-styled view of the same message. Old links and
            bookmarks still open the message they named — the id moves from the
            path into `?selected=`. */}
        <Route path="/inbox" element={<InboxPage />} />
        <Route path="/inbox/:emailId" element={<InboxMessageRedirect />} />
        <Route path="/sender-lists" element={<SenderListsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Route>

      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
