import React, { useState } from 'react';
import {
  Search,
  Bell,
  Zap,
  Globe,
  Pause,
  Play,
  Shield,
} from 'lucide-react';

interface HeaderProps {
  activeTab: string;
  isStreaming: boolean;
  setIsStreaming: (streaming: boolean) => void;
  onOpenSearch: () => void;
  onSimulateAttack: () => void;
  blockedCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  isStreaming,
  setIsStreaming,
  onOpenSearch,
  onSimulateAttack,
  blockedCount,
}) => {
  const [environment, setEnvironment] = useState('prod-us-east-1');
  const [showNotifications, setShowNotifications] = useState(false);

  const getBreadcrumbTitle = () => {
    switch (activeTab) {
      case 'oracle':
        return 'AI Threat Oracle';
      case 'ccfh':
        return 'Sequence Integrity Engine (CCFH)';
      case 'policy':
        return 'Zero-Trust Policy Matrix';
      case 'simulator':
        return 'Attack Simulator Sandbox';
      case 'nodes':
        return 'Gateway Edge Proxy Nodes';
      default:
        return 'Live Gateway Telemetry';
    }
  };

  return (
    <header className="h-16 bg-slate-950/80 backdrop-blur-md border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Left Breadcrumb */}
      <div className="flex items-center gap-2 text-xs font-medium">
        <span className="text-slate-400 flex items-center gap-1.5">
          <Shield className="w-3.5 h-3.5 text-slate-400" />
          Workspace
        </span>
        <span className="text-slate-400">/</span>
        <span className="text-slate-400">API Gateway</span>
        <span className="text-slate-400">/</span>
        <span className="text-slate-100 font-semibold font-mono tracking-wide px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
          {getBreadcrumbTitle()}
        </span>
      </div>

      {/* Right Header Status Badges & Controls */}
      <div className="flex items-center gap-3">
        {/* Live Streaming Toggle */}
        <button
          onClick={() => setIsStreaming(!isStreaming)}
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-medium border transition-all ${
            isStreaming
              ? 'bg-slate-900 text-emerald-400 border-emerald-500/30 hover:bg-slate-800'
              : 'bg-amber-500/10 text-amber-400 border-amber-500/30 hover:bg-amber-500/20'
          }`}
          title={isStreaming ? 'Pause live stream feed' : 'Resume live stream feed'}
        >
          {isStreaming ? (
            <>
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <Pause className="w-3 h-3 text-emerald-400" />
              <span>LIVE</span>
            </>
          ) : (
            <>
              <span className="w-2 h-2 rounded-full bg-amber-400"></span>
              <Play className="w-3 h-3 text-amber-400" />
              <span>PAUSED</span>
            </>
          )}
        </button>

        {/* Gateway Status Badge */}
        <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900/90 border border-slate-800 text-xs text-slate-300">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="font-mono text-[11px] font-medium text-slate-200">Inline & Enforcing</span>
        </div>

        {/* Latency Badge */}
        <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900/80 border border-slate-800 text-[11px] font-mono text-slate-300">
          <Zap className="w-3 h-3 text-blue-400" />
          <span className="text-slate-400">p99:</span>
          <span className="text-emerald-400 font-semibold">12ms</span>
        </div>

        {/* Quick Search Trigger */}
        <button
          onClick={onOpenSearch}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 text-xs hover:border-slate-700 transition-all font-mono"
        >
          <Search className="w-3.5 h-3.5 text-slate-400" />
          <span className="hidden md:inline">Search hashes or endpoints...</span>
          <kbd className="hidden sm:inline-block px-1.5 py-0.5 text-[10px] bg-slate-800 text-slate-400 rounded border border-slate-700">
            ⌘K
          </kbd>
        </button>

        {/* Quick Attack Simulator Action */}
        <button
          onClick={onSimulateAttack}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 border border-rose-500/30 text-xs font-semibold font-mono transition-all shadow-sm"
        >
          <Zap className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
          <span className="hidden sm:inline">Simulate Attack</span>
        </button>

        {/* Environment Picker */}
        <div className="hidden xl:flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-300 font-mono">
          <Globe className="w-3.5 h-3.5 text-blue-400" />
          <select
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
            className="bg-transparent border-none text-xs text-slate-200 focus:outline-none cursor-pointer"
          >
            <option value="prod-us-east-1" className="bg-slate-900">prod-us-east-1</option>
            <option value="prod-eu-west-1" className="bg-slate-900">prod-eu-west-1</option>
            <option value="staging-us-west-2" className="bg-slate-900">staging-us-west-2</option>
          </select>
        </div>

        {/* Notification Bell */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-all"
          >
            <Bell className="w-4 h-4" />
            {blockedCount > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-rose-500 text-white text-[10px] font-mono font-bold flex items-center justify-center border border-slate-950">
                {blockedCount}
              </span>
            )}
          </button>

          {/* Notifications Dropdown Popup */}
          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 rounded-xl bg-slate-900 border border-slate-800 shadow-2xl p-4 z-50 text-xs space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="font-semibold text-slate-100 flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-rose-400" />
                  Security Alerts ({blockedCount})
                </span>
                <span className="text-[10px] text-slate-400 font-mono">Q-SAFE Engine</span>
              </div>
              <div className="space-y-2 max-h-60 overflow-y-auto">
                <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-300 space-y-1">
                  <div className="flex justify-between font-mono font-semibold text-[11px]">
                    <span>BOLA Intercepted</span>
                    <span className="text-slate-400 text-[10px]">Just now</span>
                  </div>
                  <p className="text-[11px] text-slate-300">
                    Order refund sequence mismatch on <code>/api/v1/orders/99</code>
                  </p>
                </div>
                <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 space-y-1">
                  <div className="flex justify-between font-mono font-semibold text-[11px]">
                    <span>BFLA Escalation Attempt</span>
                    <span className="text-slate-400 text-[10px]">5m ago</span>
                  </div>
                  <p className="text-[11px] text-slate-300">
                    Role 'AnonymousGuest' attempted admin cluster config read
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* User Profile */}
        <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
          <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-semibold text-blue-400 font-mono">
            SO
          </div>
          <div className="hidden lg:flex flex-col text-left">
            <span className="text-xs font-medium text-slate-200">SecOps Admin</span>
            <span className="text-[10px] text-slate-400 font-mono">SOC Tier 3</span>
          </div>
        </div>
      </div>
    </header>
  );
};
