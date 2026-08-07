import React from 'react';
import { ExecutiveMetric } from '../types';
import { ResponsiveContainer, AreaChart, Area } from 'recharts';
import {
  Activity,
  ShieldAlert,
  GitBranch,
  Zap,
  ArrowUpRight,
  ArrowDownRight,
} from 'lucide-react';

interface ExecutiveMetricsProps {
  metrics: ExecutiveMetric[];
  blockedCount: number;
}

export const ExecutiveMetrics: React.FC<ExecutiveMetricsProps> = ({ metrics, blockedCount }) => {
  const getCardIcon = (index: number) => {
    switch (index) {
      case 0:
        return <Activity className="w-5 h-5 text-emerald-400" />;
      case 1:
        return <ShieldAlert className="w-5 h-5 text-rose-400" />;
      case 2:
        return <GitBranch className="w-5 h-5 text-blue-400" />;
      case 3:
      default:
        return <Zap className="w-5 h-5 text-emerald-400" />;
    }
  };

  const getCardColors = (color: string) => {
    switch (color) {
      case 'rose':
        return {
          bg: 'bg-rose-950/20 hover:bg-rose-950/30 border-rose-500/30',
          text: 'text-rose-400',
          badgeBg: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
          stroke: '#f43f5e',
          gradient: '#f43f5e',
        };
      case 'amber':
        return {
          bg: 'bg-amber-950/20 hover:bg-amber-950/30 border-amber-500/30',
          text: 'text-amber-400',
          badgeBg: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
          stroke: '#f59e0b',
          gradient: '#f59e0b',
        };
      case 'blue':
        return {
          bg: 'bg-blue-950/20 hover:bg-blue-950/30 border-blue-500/30',
          text: 'text-blue-400',
          badgeBg: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
          stroke: '#3b82f6',
          gradient: '#3b82f6',
        };
      case 'emerald':
      default:
        return {
          bg: 'bg-slate-900/60 hover:bg-slate-900/80 border-slate-800/80',
          text: 'text-emerald-400',
          badgeBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
          stroke: '#10b981',
          gradient: '#10b981',
        };
    }
  };

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {metrics.map((metric, idx) => {
        const style = getCardColors(metric.color);
        const chartData = metric.sparklineData.map((val, i) => ({ val, i }));
        const isBlockedCard = idx === 1;
        const displayValue = isBlockedCard ? `${blockedCount} Blocked` : metric.value;

        return (
          <div
            key={metric.title}
            className={`rounded-xl p-4 border backdrop-blur-md transition-all duration-200 relative overflow-hidden group ${style.bg}`}
          >
            {/* Top Row: Icon + Badge */}
            <div className="flex items-center justify-between mb-2">
              <div className="p-2 rounded-lg bg-slate-900/90 border border-slate-800 shadow-inner">
                {getCardIcon(idx)}
              </div>
              {metric.badgeText && (
                <span
                  className={`text-[10px] font-mono font-medium px-2 py-0.5 rounded-full border ${style.badgeBg}`}
                >
                  {metric.badgeText}
                </span>
              )}
            </div>

            {/* Metric Value & Title */}
            <div className="space-y-1 z-10 relative">
              <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">
                {metric.title}
              </span>
              <div className="flex items-baseline justify-between">
                <h3 className="text-2xl font-bold font-mono tracking-tight text-slate-100">
                  {displayValue}
                </h3>
                <div className="flex items-center gap-0.5 text-xs font-mono font-medium text-slate-400">
                  {metric.trend === 'up' && (
                    <ArrowUpRight className={`w-3.5 h-3.5 ${style.text}`} />
                  )}
                  {metric.trend === 'down' && (
                    <ArrowDownRight className="w-3.5 h-3.5 text-emerald-400" />
                  )}
                  <span className={idx === 1 ? 'text-rose-400 font-semibold' : 'text-slate-300'}>
                    {metric.change}
                  </span>
                </div>
              </div>
            </div>

            {/* Mini Sparkline Chart */}
            <div className="h-10 mt-3 w-full opacity-80 group-hover:opacity-100 transition-opacity">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id={`grad-${idx}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={style.stroke} stopOpacity={0.4} />
                      <stop offset="100%" stopColor={style.stroke} stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <Area
                    type="monotone"
                    dataKey="val"
                    stroke={style.stroke}
                    strokeWidth={2}
                    fill={`url(#grad-${idx})`}
                    isAnimationActive={true}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        );
      })}
    </div>
  );
};
