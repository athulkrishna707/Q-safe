import React, { useState } from 'react';
import { ApiRequestLog } from '../types';
import {
  Search,
  Copy,
  Check,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  ChevronRight,
} from 'lucide-react';

interface LiveThreatFeedProps {
  logs: ApiRequestLog[];
  selectedLog: ApiRequestLog | null;
  onSelectLog: (log: ApiRequestLog) => void;
  isStreaming: boolean;
}

export const LiveThreatFeed: React.FC<LiveThreatFeedProps> = ({
  logs,
  selectedLog,
  onSelectLog,
  isStreaming,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'ALLOWED' | 'BLOCKED' | 'BOLA' | 'BFLA'>('ALL');
  const [methodFilter, setMethodFilter] = useState<string>('ALL');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const handleCopyHash = (e: React.MouseEvent, hash: string) => {
    e.stopPropagation();
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 1500);
  };

  const filteredLogs = logs.filter((log) => {
    // Status / Threat filter
    if (statusFilter === 'ALLOWED' && log.status !== 'ALLOWED') return false;
    if (statusFilter === 'BLOCKED' && log.status !== 'BLOCKED') return false;
    if (statusFilter === 'BOLA' && log.threatType !== 'BOLA') return false;
    if (statusFilter === 'BFLA' && log.threatType !== 'BFLA') return false;

    // Method filter
    if (methodFilter !== 'ALL' && log.method !== methodFilter) return false;

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        log.endpoint.toLowerCase().includes(q) ||
        log.userId.toLowerCase().includes(q) ||
        log.contextHash.toLowerCase().includes(q) ||
        log.id.toLowerCase().includes(q)
      );
    }

    return true;
  });

  const getMethodBadge = (method: string) => {
    switch (method) {
      case 'GET':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      case 'POST':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'PUT':
      case 'PATCH':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'DELETE':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl flex flex-col h-[520px] overflow-hidden shadow-xl">
      {/* Header Bar with Title & Filters */}
      <div className="p-4 border-b border-slate-800/80 space-y-3 bg-slate-950/60">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400">
              <Terminal className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                Live Gateway Feed
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700 font-normal">
                  {filteredLogs.length} events
                </span>
              </h2>
              <p className="text-[11px] text-slate-400">
                Zero-Trust API endpoint inspection stream
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono text-slate-400 hidden sm:inline">
              Stream:{' '}
              {isStreaming ? (
                <span className="text-emerald-400 font-semibold">Active</span>
              ) : (
                <span className="text-amber-400 font-semibold">Paused</span>
              )}
            </span>
          </div>
        </div>

        {/* Filters Controls Bar */}
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
          {/* Search bar */}
          <div className="relative flex-1 min-w-[180px]">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Filter endpoint, user, or hash..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-slate-700 font-mono"
            />
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1 overflow-x-auto pb-1 sm:pb-0">
            {(['ALL', 'BLOCKED', 'ALLOWED', 'BOLA', 'BFLA'] as const).map((filter) => {
              const isActive = statusFilter === filter;
              return (
                <button
                  key={filter}
                  onClick={() => setStatusFilter(filter)}
                  className={`px-2.5 py-1 rounded-md text-[11px] font-mono font-medium transition-all ${
                    isActive
                      ? filter === 'BLOCKED' || filter === 'BOLA' || filter === 'BFLA'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                        : 'bg-slate-800 text-slate-100 border border-slate-700 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'
                  }`}
                >
                  {filter}
                </button>
              );
            })}

            {/* Method Select */}
            <select
              value={methodFilter}
              onChange={(e) => setMethodFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-md px-2 py-1 text-[11px] text-slate-300 font-mono focus:outline-none cursor-pointer"
            >
              <option value="ALL">ALL METHODS</option>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
            </select>
          </div>
        </div>
      </div>

      {/* Table Feed View */}
      <div className="flex-1 overflow-y-auto">
        <table className="w-full text-left text-xs font-sans border-collapse">
          <thead className="bg-slate-950/90 text-slate-400 font-mono text-[10px] uppercase tracking-wider sticky top-0 z-10 border-b border-slate-800/80">
            <tr>
              <th className="py-2.5 px-3">Time</th>
              <th className="py-2.5 px-3">Endpoint</th>
              <th className="py-2.5 px-3 hidden md:table-cell">User / Role</th>
              <th className="py-2.5 px-3 font-mono">Context Hash</th>
              <th className="py-2.5 px-3 text-right">Latency</th>
              <th className="py-2.5 px-3 text-right">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/40">
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center py-12 text-slate-500 font-mono text-xs">
                  No request telemetry matching filters.
                </td>
              </tr>
            ) : (
              filteredLogs.map((log) => {
                const isSelected = selectedLog?.id === log.id;
                const isBlocked = log.status === 'BLOCKED';

                return (
                  <tr
                    key={log.id}
                    onClick={() => onSelectLog(log)}
                    className={`cursor-pointer transition-all duration-150 group relative ${
                      isSelected
                        ? isBlocked
                          ? 'bg-rose-950/30 border-l-4 border-l-rose-500 text-slate-100'
                          : 'bg-slate-800/80 border-l-4 border-l-blue-500 text-slate-100'
                        : isBlocked
                        ? 'bg-rose-950/10 hover:bg-rose-950/25 border-l-2 border-l-rose-500/80 text-slate-200'
                        : 'hover:bg-slate-800/40 text-slate-300'
                    }`}
                  >
                    {/* Timestamp */}
                    <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                      {log.timestamp}
                    </td>

                    {/* Method + Endpoint */}
                    <td className="py-2.5 px-3 font-mono text-xs max-w-[200px] lg:max-w-[240px] truncate">
                      <span
                        className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border mr-2 uppercase ${getMethodBadge(
                          log.method
                        )}`}
                      >
                        {log.method}
                      </span>
                      <span className="text-slate-200 group-hover:text-white font-medium">
                        {log.endpoint}
                      </span>
                    </td>

                    {/* User & Role */}
                    <td className="py-2.5 px-3 text-xs hidden md:table-cell whitespace-nowrap">
                      <div className="flex flex-col">
                        <span className="text-slate-200 font-mono text-[11px] font-medium">
                          {log.userId}
                        </span>
                        <span className="text-[10px] text-slate-400">{log.userRole}</span>
                      </div>
                    </td>

                    {/* Context Hash */}
                    <td className="py-2.5 px-3 font-mono text-xs whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[11px] ${
                            isBlocked
                              ? 'bg-rose-500/10 text-rose-300 border border-rose-500/20'
                              : 'bg-blue-500/10 text-blue-300 border border-blue-500/20'
                          }`}
                        >
                          {log.contextHash}
                        </span>
                        <button
                          onClick={(e) => handleCopyHash(e, log.contextHash)}
                          className="opacity-0 group-hover:opacity-100 p-1 text-slate-400 hover:text-slate-200 transition-opacity"
                          title="Copy context hash"
                        >
                          {copiedHash === log.contextHash ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </td>

                    {/* Latency */}
                    <td className="py-2.5 px-3 text-right font-mono text-xs text-slate-400 whitespace-nowrap">
                      {log.latencyMs}ms
                    </td>

                    {/* Status Pill */}
                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5">
                        {isBlocked ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 text-[10px] font-mono font-bold shadow-sm">
                            <ShieldAlert className="w-3 h-3 text-rose-400" />
                            BLOCKED
                            {log.threatType !== 'NONE' && (
                              <span className="ml-1 px-1 py-0.2 rounded bg-rose-950 text-rose-300 text-[9px]">
                                {log.threatType}
                              </span>
                            )}
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] font-mono font-semibold">
                            <ShieldCheck className="w-3 h-3 text-emerald-400" />
                            ALLOWED
                          </span>
                        )}
                        <ChevronRight className="w-3.5 h-3.5 text-slate-600 group-hover:text-slate-300 transition-colors" />
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
