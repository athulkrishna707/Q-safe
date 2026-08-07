import React from 'react';
import {
  ShieldCheck,
  Activity,
  Sliders,
  Brain,
  Zap,
  Server,
  ChevronLeft,
  ChevronRight,
  GitBranch,
  Lock,
} from 'lucide-react';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  collapsed: boolean;
  setCollapsed: (collapsed: boolean) => void;
  blockedCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  collapsed,
  setCollapsed,
  blockedCount,
}) => {
  const navItems = [
    {
      id: 'monitor',
      label: 'Live Monitor',
      icon: Activity,
      badge: null,
      description: 'Real-time API gateway telemetry',
    },
    {
      id: 'oracle',
      label: 'AI Threat Oracle',
      icon: Brain,
      badge: blockedCount > 0 ? `${blockedCount}` : null,
      badgeColor: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
      description: 'Agentic forensic explainability engine',
    },
    {
      id: 'ccfh',
      label: 'Sequence Integrity',
      icon: GitBranch,
      badge: 'CCFH',
      badgeColor: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      description: 'Contextual Control Flow Hashing graph',
    },
    {
      id: 'policy',
      label: 'Policy Engine',
      icon: Sliders,
      badge: 'Zero-Trust',
      badgeColor: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
      description: 'Active authorization rules & enforcement',
    },
    {
      id: 'simulator',
      label: 'Attack Simulator',
      icon: Zap,
      badge: 'Sandbox',
      badgeColor: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
      description: 'Simulate BFLA, BOLA & token exploits',
    },
    {
      id: 'nodes',
      label: 'Edge Nodes',
      icon: Server,
      badge: '3 Online',
      badgeColor: 'bg-slate-800 text-slate-300 border-slate-700',
      description: 'Cluster health & gateway edge proxies',
    },
  ];

  return (
    <aside
      className={`fixed top-0 left-0 bottom-0 z-40 bg-slate-950/95 backdrop-blur-md border-r border-slate-800/80 flex flex-col justify-between transition-all duration-300 ${
        collapsed ? 'w-18' : 'w-64'
      }`}
    >
      {/* Top Header Logo */}
      <div>
        <div className="h-16 px-4 flex items-center justify-between border-b border-slate-800/80">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-gradient-to-br from-blue-600/30 to-slate-900 border border-blue-500/40 text-blue-400 shadow-lg shadow-blue-950/50 shrink-0">
              <ShieldCheck className="w-5 h-5 text-blue-400" />
              <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
              </span>
            </div>
            {!collapsed && (
              <div className="flex flex-col">
                <span className="font-bold text-slate-100 tracking-wider text-base font-mono flex items-center gap-1.5">
                  Q-SAFE
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-sans font-medium">
                    v2.4
                  </span>
                </span>
                <span className="text-[11px] text-slate-400 font-medium truncate">
                  Zero-Trust API Gateway
                </span>
              </div>
            )}
          </div>
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors border border-transparent hover:border-slate-700"
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Items */}
        <nav className="p-2 space-y-1 mt-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all group relative ${
                  isActive
                    ? 'bg-slate-800/90 text-slate-100 border border-slate-700/80 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                }`}
                title={collapsed ? `${item.label}: ${item.description}` : undefined}
              >
                {/* Active indicator highlight strip */}
                {isActive && (
                  <span className="absolute left-0 top-2 bottom-2 w-1 rounded-r bg-blue-500 shadow-sm shadow-blue-500" />
                )}
                <Icon
                  className={`w-4 h-4 shrink-0 transition-colors ${
                    isActive ? 'text-blue-400' : 'text-slate-400 group-hover:text-slate-300'
                  }`}
                />
                {!collapsed && (
                  <div className="flex-1 text-left flex items-center justify-between overflow-hidden">
                    <span className="truncate">{item.label}</span>
                    {item.badge && (
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded border font-mono font-medium ml-1.5 shrink-0 ${
                          item.badgeColor || 'bg-slate-800 text-slate-300 border-slate-700'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </div>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer Node Info */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-950">
        {!collapsed ? (
          <div className="rounded-lg p-2.5 bg-slate-900/60 border border-slate-800/80 text-[11px] space-y-2">
            <div className="flex items-center justify-between text-slate-400 font-mono">
              <span className="flex items-center gap-1.5 text-slate-300 font-medium">
                <Lock className="w-3 h-3 text-emerald-400" /> CCFH Enforcer
              </span>
              <span className="text-emerald-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                ACTIVE
              </span>
            </div>
            <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1 border-t border-slate-800/60 font-mono">
              <span>Node ID: sgw-us-east-4a</span>
              <span className="text-blue-400">99.998% Uptime</span>
            </div>
          </div>
        ) : (
          <div className="flex justify-center" title="Gateway Active: sgw-us-east-4a">
            <div className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse border-2 border-slate-950" />
          </div>
        )}
      </div>
    </aside>
  );
};
