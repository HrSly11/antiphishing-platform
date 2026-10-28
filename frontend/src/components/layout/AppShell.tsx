import { useEffect, useState } from 'react';
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  Crosshair,
  Database,
  FileSpreadsheet,
  Globe,
  KeyRound,
  LayoutDashboard,
  Lock,
  LogOut,
  MailCheck,
  Menu,
  Moon,
  Scale,
  Shield,
  ShieldAlert,
  Sun,
  Target,
  Users,
  X,
} from 'lucide-react';
import { checkApiHealth } from '../../api/queries/useAnalyze';
import { getRoleBadgeClasses } from '../../lib/formatters';
import { translateText } from '../../lib/i18n';
import { PERMISSIONS } from '../../lib/permissions';
import { useAuthStore } from '../../stores/authStore';
import { useLanguageStore } from '../../stores/languageStore';
import { useThemeStore } from '../../stores/themeStore';
import MfaModal from '../auth/MfaModal';
import SocChatWidget from '../SocChatWidget';

interface NavItem {
  path: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  permission?: string;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    title: 'Command & Telemetry',
    items: [
      {
        path: '/dashboard',
        label: 'Analytical Dashboard',
        icon: LayoutDashboard,
        permission: PERMISSIONS.DASHBOARD_READ,
      },
      {
        path: '/analyze',
        label: 'Gateway & Multi-Analyzer',
        icon: MailCheck,
      },
    ],
  },
  {
    title: 'SOC Operations',
    items: [
      {
        path: '/verdicts',
        label: 'Detection Verdicts',
        icon: ShieldAlert,
        permission: PERMISSIONS.DETECTION_READ,
      },
      {
        path: '/incidents',
        label: 'SOC Incidents & SLA',
        icon: AlertTriangle,
        permission: PERMISSIONS.INCIDENTS_READ,
      },
      {
        path: '/iocs',
        label: 'Dynamic IOC Lists',
        icon: Shield,
        permission: PERMISSIONS.IOCS_READ,
      },
      {
        path: '/threat-hunting',
        label: 'Threat Hunting (pg_trgm)',
        icon: Crosshair,
        permission: PERMISSIONS.HUNTING_READ,
      },
    ],
  },
  {
    title: 'Governance & GRC',
    items: [
      {
        path: '/reports',
        label: 'Reports & Schedules',
        icon: FileSpreadsheet,
        permission: PERMISSIONS.REPORTS_READ,
      },
      {
        path: '/dataset',
        label: 'Public Dataset & ETL',
        icon: Database,
        permission: PERMISSIONS.DATASET_READ,
      },
      {
        path: '/simulation',
        label: 'Phishing Simulation',
        icon: Target,
        permission: PERMISSIONS.DETECTION_READ,
      },
      {
        path: '/audit',
        label: 'Compliance & Audit Chain',
        icon: Scale,
        permission: PERMISSIONS.AUDIT_READ,
      },
      {
        path: '/users',
        label: 'RBAC Users & MFA',
        icon: Users,
        permission: PERMISSIONS.USERS_READ,
      },
    ],
  },
];

export function AppShell() {
  const location = useLocation();
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const hasPermission = useAuthStore((s) => s.hasPermission);
  const logout = useAuthStore((s) => s.logout);

  const theme = useThemeStore((s) => s.theme);
  const toggleTheme = useThemeStore((s) => s.toggleTheme);
  const lang = useLanguageStore((s) => s.lang);
  const toggleLang = useLanguageStore((s) => s.toggleLang);
  const tr = (text: string) => translateText(text, lang);

  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [mfaModalOpen, setMfaModalOpen] = useState(false);
  const [showPermsPopover, setShowPermsPopover] = useState(false);
  const [health, setHealth] = useState<{ healthy: boolean; dbReady: boolean } | null>(null);

  useEffect(() => {
    let active = true;
    const poll = () => {
      checkApiHealth().then((res) => {
        if (active) setHealth(res);
      });
    };
    poll();
    const timer = setInterval(poll, 30000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  const permissionsList = user?.permissions ?? [];

  return (
    <div className="min-h-screen flex bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      {/* Sidebar (Desktop + Mobile Drawer) */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 w-64 transform border-r border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 transition-transform duration-200 lg:static lg:translate-x-0 flex flex-col ${
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="h-16 px-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <Link to="/dashboard" className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-700 text-white flex items-center justify-center shadow-md shadow-blue-900/20">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="font-bold text-sm tracking-tight text-slate-900 dark:text-white leading-tight">
                SentinelBank SOC
              </div>
              <div className="text-[10px] font-mono text-blue-600 dark:text-blue-400">
                PCI-DSS 4.0 · ISO 27001
              </div>
            </div>
          </Link>
          <button
            type="button"
            onClick={() => setMobileMenuOpen(false)}
            className="lg:hidden p-1.5 rounded-lg text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
          {NAV_GROUPS.map((group) => (
            <div key={group.title} className="space-y-1">
              <div className="px-2.5 text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                {tr(group.title)}
              </div>
              {group.items.map((item) => {
                const Icon = item.icon;
                const allowed = item.permission ? hasPermission(item.permission) : true;
                const active =
                  location.pathname === item.path ||
                  (item.path !== '/dashboard' && location.pathname.startsWith(item.path));

                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    onClick={() => setMobileMenuOpen(false)}
                    title={
                      allowed
                        ? tr(item.label)
                        : tr(`Requires '${item.permission}' (restricted for role ${user?.role ?? ''})`)
                    }
                    className={`flex items-center justify-between gap-2 px-2.5 py-2 rounded-lg text-xs font-medium transition ${
                      active
                        ? 'bg-blue-600 text-white shadow-sm'
                        : allowed
                          ? 'text-slate-700 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800/80'
                          : 'text-slate-400 dark:text-slate-600 hover:bg-slate-100/60 dark:hover:bg-slate-900'
                    }`}
                  >
                    <span className="flex items-center gap-2.5 truncate">
                      <Icon className="w-4 h-4 shrink-0" />
                      <span className="truncate">{tr(item.label)}</span>
                    </span>
                    {!allowed && <Lock className="w-3.5 h-3.5 text-amber-500/80 shrink-0" />}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>

        <div className="p-3 border-t border-slate-200 dark:border-slate-800 text-[11px] text-slate-500 dark:text-slate-400 space-y-1">
          <div className="flex items-center justify-between">
            <span>{tr('Architecture')}</span>
            <span className="font-mono text-slate-700 dark:text-slate-300">Hexagonal + CQRS</span>
          </div>
          <div className="flex items-center justify-between">
            <span>{tr('AI Inference')}</span>
            <span className="font-mono text-emerald-600 dark:text-emerald-400">100% On-Premise</span>
          </div>
        </div>
      </aside>

      {/* Mobile Backdrop */}
      {mobileMenuOpen && (
        <div
          onClick={() => setMobileMenuOpen(false)}
          className="fixed inset-0 z-30 bg-slate-950/60 lg:hidden"
        />
      )}

      {/* Main Column */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Topbar */}
        <header className="h-16 sticky top-0 z-20 border-b border-slate-200 bg-white/90 dark:border-slate-800 dark:bg-slate-900/90 backdrop-blur px-4 lg:px-6 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-2 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300"
            >
              <Menu className="w-4 h-4" />
            </button>

            {/* Live Backend & PostgreSQL Indicator */}
            <div
              className={`inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-[11px] font-semibold border ${
                health === null
                  ? 'bg-slate-100 text-slate-600 border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700'
                  : health.healthy && health.dbReady
                    ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                    : 'bg-red-500/10 text-red-700 dark:text-red-300 border-red-500/30'
              }`}
              title="FastAPI /health & PostgreSQL /ready live status"
            >
              <Activity className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">
                {health === null
                  ? tr('Probing API...')
                  : health.healthy && health.dbReady
                    ? tr('API & PostgreSQL Ready')
                    : tr('Backend Degraded')}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-3">
            {user && (
              <div className="relative flex items-center gap-2">
                <div className="hidden md:block text-right">
                  <div className="text-xs font-bold text-slate-900 dark:text-white leading-tight">
                    {user.full_name}
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                    {user.email}
                  </div>
                </div>

                <span
                  className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold border ${getRoleBadgeClasses(
                    user.role,
                  )}`}
                >
                  {user.role}
                </span>

                <button
                  type="button"
                  onClick={() => setShowPermsPopover((v) => !v)}
                  className="px-2 py-0.5 rounded text-[11px] font-mono border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:border-blue-500"
                  title={tr('Inspect granted RBAC permissions')}
                >
                  {lang === 'es' ? `${permissionsList.length} permisos` : `${permissionsList.length} perms`}
                </button>

                {showPermsPopover && (
                  <div className="absolute right-0 top-10 z-50 w-72 soc-card p-3 shadow-xl space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="soc-label">{tr('Active RBAC Capabilities')}</span>
                      <button
                        type="button"
                        onClick={() => setShowPermsPopover(false)}
                        className="text-slate-400 hover:text-slate-700 dark:hover:text-white"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {permissionsList.map((p) => (
                        <span
                          key={p}
                          className="px-1.5 py-0.5 rounded font-mono text-[10px] bg-blue-500/10 text-blue-700 dark:text-blue-300 border border-blue-500/20"
                        >
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* MFA Setup Trigger */}
            <button
              type="button"
              onClick={() => setMfaModalOpen(true)}
              className={`soc-btn-secondary px-2.5 py-1.5 ${
                user?.mfa_enabled
                  ? 'border-emerald-500/40 text-emerald-700 dark:text-emerald-300'
                  : ''
              }`}
              title={tr('Configure RFC 6238 TOTP Multi-Factor Authentication')}
            >
              <KeyRound className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{user?.mfa_enabled ? tr('MFA On') : 'MFA'}</span>
            </button>

            {/* Language Toggle (ES / EN) */}
            <button
              type="button"
              onClick={toggleLang}
              className="soc-btn-secondary px-2.5 py-1.5 font-mono text-xs"
              title={
                lang === 'es'
                  ? 'Cambiar idioma a Inglés (Switch to English)'
                  : 'Switch language to Spanish (Cambiar a Español)'
              }
            >
              <Globe className="w-3.5 h-3.5 text-blue-500" />
              <span className={lang === 'es' ? 'font-bold text-blue-600 dark:text-blue-400' : 'opacity-60'}>
                ES
              </span>
              <span className="opacity-40">/</span>
              <span className={lang === 'en' ? 'font-bold text-blue-600 dark:text-blue-400' : 'opacity-60'}>
                EN
              </span>
            </button>

            {/* Theme Toggle */}
            <button
              type="button"
              onClick={toggleTheme}
              className="soc-btn-secondary px-2.5 py-1.5"
              title={
                theme === 'dark'
                  ? tr('Switch to Light Executive Mode')
                  : tr('Switch to Dark SOC Operations Mode')
              }
            >
              {theme === 'dark' ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
              <span className="hidden xl:inline">
                {theme === 'dark' ? tr('Light') : tr('Dark')}
              </span>
            </button>

            {/* Logout */}
            <button
              type="button"
              onClick={handleLogout}
              className="soc-btn-danger px-2.5 py-1.5"
              title={tr('Sign out and record session logout in immutable audit trail')}
            >
              <LogOut className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{tr('Logout')}</span>
            </button>
          </div>
        </header>

        {/* Active Page Outlet */}
        <main className="flex-1 overflow-x-hidden pb-16">
          <Outlet />
        </main>
      </div>

      {/* Self-service TOTP MFA Modal */}
      <MfaModal open={mfaModalOpen} onClose={() => setMfaModalOpen(false)} />

      {/* Persistent SOC AI Copilot & LangFlow Sandbox */}
      <SocChatWidget />
    </div>
  );
}

export default AppShell;
