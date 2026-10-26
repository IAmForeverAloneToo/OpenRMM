import { lazy, Suspense } from "react";
import { Link, Route, Routes } from "react-router";
import { useSession } from "./lib/session";
import { AppShell } from "./app/AppShell";
import { Login } from "./pages/Login";
import { Activate } from "./pages/Activate";
import { Setup } from "./pages/Setup";
import { Dashboard } from "./pages/Dashboard";
import { Devices } from "./pages/Devices";
import { DeviceConsole } from "./pages/DeviceConsole";
import { EmptyState, ErrorNotice, Spinner } from "./components/ui";

// Live tools load their heavier code (terminal emulator) only when opened.
const TerminalPage = lazy(() => import("./pages/TerminalPage").then((m) => ({ default: m.TerminalPage })));
const ScriptsPage = lazy(() => import("./pages/scripts/ScriptsPage").then((m) => ({ default: m.ScriptsPage })));
const BatchNew = lazy(() => import("./pages/scripts/BatchPages").then((m) => ({ default: m.BatchNew })));
const BatchDetail = lazy(() => import("./pages/scripts/BatchPages").then((m) => ({ default: m.BatchDetail })));
const AlertsPage = lazy(() => import("./pages/alerts/AlertsPage").then((m) => ({ default: m.AlertsPage })));
const AlertSettingsPage = lazy(() => import("./pages/alerts/AlertSettingsPage").then((m) => ({ default: m.AlertSettingsPage })));
const HealthChecksPage = lazy(() => import("./pages/alerts/HealthChecksPage").then((m) => ({ default: m.HealthChecksPage })));
const ScriptEditor = lazy(() => import("./pages/scripts/ScriptEditor").then((m) => ({ default: m.ScriptEditor })));
const PatchingPage = lazy(() => import("./pages/operations/PatchingPage").then((m) => ({ default: m.PatchingPage })));
const AppsPage = lazy(() => import("./pages/operations/AppsPage").then((m) => ({ default: m.AppsPage })));
const AgentUpdatesPage = lazy(() => import("./pages/operations/AgentUpdatesPage").then((m) => ({ default: m.AgentUpdatesPage })));
const MetricsReport = lazy(() => import("./pages/reports/MetricsReport").then((m) => ({ default: m.MetricsReport })));
const SoftwareReport = lazy(() => import("./pages/reports/SoftwareReport").then((m) => ({ default: m.SoftwareReport })));
const OrganizationPage = lazy(() => import("./pages/admin/OrganizationPage").then((m) => ({ default: m.OrganizationPage })));
const ServerUpdatesPage = lazy(() => import("./pages/admin/ServerUpdatesPage").then((m) => ({ default: m.ServerUpdatesPage })));
const BackupsPage = lazy(() => import("./pages/admin/BackupsPage").then((m) => ({ default: m.BackupsPage })));
const TechniciansPage = lazy(() => import("./pages/admin/TechniciansPage").then((m) => ({ default: m.TechniciansPage })));
const CasesPage = lazy(() => import("./pages/cases/CasesPage").then((m) => ({ default: m.CasesPage })));
const CasePage = lazy(() => import("./pages/cases/CasePage").then((m) => ({ default: m.CasePage })));
const HuntingPage = lazy(() => import("./pages/hunting/HuntingPage").then((m) => ({ default: m.HuntingPage })));
const HuntPage = lazy(() => import("./pages/hunting/HuntPage").then((m) => ({ default: m.HuntPage })));
const DesktopPage = lazy(() => import("./pages/DesktopPage").then((m) => ({ default: m.DesktopPage })));
const opening = (
  <div className="flex min-h-screen items-center justify-center">
    <Spinner label="Opening session" />
  </div>
);

function NotFound() {
  return (
    <div className="p-8">
      <EmptyState title="Page not found">
        <Link to="/" className="text-accent hover:underline">
          Go to the dashboard
        </Link>
      </EmptyState>
    </div>
  );
}

export function App() {
  const { session, loading } = useSession();
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner label="Starting" />
      </div>
    );
  }
  // Invitation links work whether or not someone is signed in on this browser.
  if (window.location.pathname === "/activate") return <Activate onDone={() => window.location.assign("/")} />;
  // The first administrator is created from the install command's link.
  if (window.location.pathname === "/setup") return <Setup onDone={() => window.location.assign("/")} />;
  if (!session) return <Login />;
  return (
    <Routes>
      {/* Live sessions open full-screen, outside the navigation shell. */}
      <Route path="devices/:id/terminal/:session" element={<Suspense fallback={opening}><TerminalPage /></Suspense>} />
      <Route path="devices/:id/desktop/:session" element={<Suspense fallback={opening}><DesktopPage /></Suspense>} />
      <Route element={<AppShell />}>
        <Route index element={<Dashboard />} />
        <Route path="devices" element={<Devices />} />
        <Route path="devices/:id" element={<DeviceConsole />} />
        <Route path="alerts" element={<Suspense fallback={<Spinner label="Loading" />}><AlertsPage /></Suspense>} />
        <Route path="settings/alerts" element={<Suspense fallback={<Spinner label="Loading" />}><AlertSettingsPage /></Suspense>} />
        <Route path="health-checks" element={<Suspense fallback={<Spinner label="Loading" />}><HealthChecksPage /></Suspense>} />
        <Route path="scripts" element={<Suspense fallback={<Spinner label="Loading" />}><ScriptsPage /></Suspense>} />
        <Route path="scripts/new" element={<Suspense fallback={<Spinner label="Loading editor" />}><ScriptEditor /></Suspense>} />
        <Route path="scripts/v/:version" element={<Suspense fallback={<Spinner label="Loading editor" />}><ScriptEditor /></Suspense>} />
        <Route path="scripts/run" element={<Suspense fallback={<Spinner label="Loading" />}><BatchNew /></Suspense>} />
        <Route path="scripts/runs/:batch" element={<Suspense fallback={<Spinner label="Loading" />}><BatchDetail /></Suspense>} />
        <Route path="patching" element={<Suspense fallback={<Spinner label="Loading" />}><PatchingPage /></Suspense>} />
        <Route path="deployments" element={<Suspense fallback={<Spinner label="Loading" />}><AppsPage /></Suspense>} />
        <Route path="agent-updates" element={<Suspense fallback={<Spinner label="Loading" />}><AgentUpdatesPage /></Suspense>} />
        <Route path="hunting" element={<Suspense fallback={<Spinner label="Loading" />}><HuntingPage /></Suspense>} />
        <Route path="hunting/:hunt" element={<Suspense fallback={<Spinner label="Loading" />}><HuntPage /></Suspense>} />
        <Route path="reports/metrics" element={<Suspense fallback={<Spinner label="Loading" />}><MetricsReport /></Suspense>} />
        <Route path="reports/software" element={<Suspense fallback={<Spinner label="Loading" />}><SoftwareReport /></Suspense>} />
        <Route path="organization" element={<Suspense fallback={<Spinner label="Loading" />}><OrganizationPage /></Suspense>} />
        <Route path="cases" element={<Suspense fallback={<Spinner label="Loading" />}><CasesPage /></Suspense>} />
        <Route path="cases/:id" element={<Suspense fallback={<Spinner label="Loading" />}><CasePage /></Suspense>} />
        <Route path="technicians" element={<Suspense fallback={<Spinner label="Loading" />}><TechniciansPage /></Suspense>} />
        <Route path="server-updates" element={<Suspense fallback={<Spinner label="Loading" />}><ServerUpdatesPage /></Suspense>} />
        <Route path="backups" element={<Suspense fallback={<Spinner label="Loading" />}><BackupsPage /></Suspense>} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}

export function FatalError({ error }: { error: unknown }) {
  return (
    <div className="p-8">
      <ErrorNotice error={error} />
    </div>
  );
}
