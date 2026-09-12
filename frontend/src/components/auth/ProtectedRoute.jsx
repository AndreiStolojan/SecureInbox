import { Fragment } from 'react';
import { Navigate, useLocation } from 'react-router-dom';

import { useAuth } from '@/hooks/useAuth';
import { LoadingState } from '@/components/common/states';

export function ProtectedRoute({ children }) {
  const { isAuthenticated, loading, session } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <LoadingState label="Checking your session…" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  // Reset account providers and page-local state on every session transition.
  return <Fragment key={session}>{children}</Fragment>;
}
