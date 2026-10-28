import React from 'react';

export interface KpiCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  accent?: 'blue' | 'red' | 'amber' | 'emerald' | 'purple';
  icon?: React.ReactNode;
}

const ACCENT_MAP: Record<NonNullable<KpiCardProps['accent']>, string> = {
  blue: 'text-blue-600 dark:text-blue-400',
  red: 'text-red-600 dark:text-red-400',
  amber: 'text-amber-600 dark:text-amber-400',
  emerald: 'text-emerald-600 dark:text-emerald-400',
  purple: 'text-purple-600 dark:text-purple-400',
};

export function KpiCard({
  title,
  value,
  subtitle,
  accent = 'blue',
  icon,
}: KpiCardProps) {
  return (
    <div className="soc-card p-4 sm:p-5 flex flex-col justify-between gap-2">
      <div className="flex items-center justify-between gap-2">
        <span className="soc-label">{title}</span>
        {icon && <span className={ACCENT_MAP[accent]}>{icon}</span>}
      </div>
      <div className={`text-2xl sm:text-3xl font-black tracking-tight ${ACCENT_MAP[accent]}`}>
        {value}
      </div>
      {subtitle && (
        <div className="text-[11px] text-slate-500 dark:text-slate-400 leading-snug">
          {subtitle}
        </div>
      )}
    </div>
  );
}

export default KpiCard;
