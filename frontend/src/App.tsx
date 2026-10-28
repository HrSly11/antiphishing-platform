import { Navigate, Route, Routes } from 'react-router-dom';
import AppShell from './components/layout/AppShell';
import AutoI18nBridge from './components/layout/AutoI18nBridge';
import AdminUsersPage from './pages/AdminUsersPage';
import AnalyzePage from './pages/AnalyzePage';
import AuditPage from './pages/AuditPage';
import DashboardPage from './pages/DashboardPage';
import DatasetPage from './pages/DatasetPage';
import ForbiddenPage from './pages/ForbiddenPage';
import IncidentDetailPage from './pages/IncidentDetailPage';
import IncidentsPage from './pages/IncidentsPage';
import IocsPage from './pages/IocsPage';
import LoginPage from './pages/LoginPage';
import NotFoundPage from './pages/NotFoundPage';
import ReportsPage from './pages/ReportsPage';
import SimulationPage from './pages/SimulationPage';
import ThreatHuntingPage from './pages/ThreatHuntingPage';
import VerdictsPage from './pages/VerdictsPage';
import { useAuthStore } from './stores/authStore';

function ProtectedShell() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return <AppShell />;
}

export default function App() {
  return (
    <>
      <AutoI18nBridge />
      <Routes>
        <Route path="/login" element={<LoginPage />} />

        <Route element={<ProtectedShell />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/analyze" element={<AnalyzePage />} />
          <Route path="/verdicts" element={<VerdictsPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/incidents/:id" element={<IncidentDetailPage />} />
          <Route path="/iocs" element={<IocsPage />} />
          <Route path="/threat-hunting" element={<ThreatHuntingPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/dataset" element={<DatasetPage />} />
          <Route path="/simulation" element={<SimulationPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/users" element={<AdminUsersPage />} />
          <Route path="/forbidden" element={<ForbiddenPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </>
  );
}
