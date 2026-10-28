import { Link } from 'react-router-dom';
import { Compass } from 'lucide-react';

export default function NotFoundPage() {
  return (
    <div className="p-8 max-w-xl mx-auto">
      <div className="soc-card p-8 text-center space-y-4">
        <div className="w-12 h-12 mx-auto rounded-full bg-blue-500/15 text-blue-500 flex items-center justify-center">
          <Compass className="w-6 h-6" />
        </div>
        <h1 className="text-xl font-bold text-slate-900 dark:text-white">404 — Route Not Found</h1>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          The requested SOC module path does not exist.
        </p>
        <Link to="/dashboard" className="soc-btn-primary">
          Go to Analytical Dashboard
        </Link>
      </div>
    </div>
  );
}
