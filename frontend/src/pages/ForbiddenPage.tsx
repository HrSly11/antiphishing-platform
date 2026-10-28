import { Link } from 'react-router-dom';
import { ShieldOff } from 'lucide-react';

export default function ForbiddenPage() {
  return (
    <div className="p-8 max-w-xl mx-auto">
      <div className="soc-card p-8 text-center space-y-4">
        <div className="w-12 h-12 mx-auto rounded-full bg-red-500/15 text-red-500 flex items-center justify-center">
          <ShieldOff className="w-6 h-6" />
        </div>
        <h1 className="text-xl font-bold text-slate-900 dark:text-white">403 — Access Restricted</h1>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Your current RBAC role does not grant permission to view this resource.
        </p>
        <Link to="/dashboard" className="soc-btn-primary">
          Return to SOC Dashboard
        </Link>
      </div>
    </div>
  );
}
