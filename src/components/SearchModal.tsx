import React, { useState, useEffect } from 'react';
import { ApiRequestLog } from '../types';
import { Search, X, ArrowRight } from 'lucide-react';

interface SearchModalProps {
  isOpen: boolean;
  onClose: () => void;
  logs: ApiRequestLog[];
  onSelectLog: (log: ApiRequestLog) => void;
}

export const SearchModal: React.FC<SearchModalProps> = ({
  isOpen,
  onClose,
  logs,
  onSelectLog,
}) => {
  const [query, setQuery] = useState('');

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!isOpen) return null;

  const results = query.trim()
    ? logs.filter(
        (l) =>
          l.endpoint.toLowerCase().includes(query.toLowerCase()) ||
          l.userId.toLowerCase().includes(query.toLowerCase()) ||
          l.contextHash.toLowerCase().includes(query.toLowerCase()) ||
          l.id.toLowerCase().includes(query.toLowerCase())
      )
    : logs.slice(0, 5);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-4 shadow-2xl relative space-y-3">
        {/* Input Bar */}
        <div className="relative flex items-center border-b border-slate-800 pb-3">
          <Search className="w-5 h-5 absolute left-2 text-slate-400" />
          <input
            type="text"
            autoFocus
            placeholder="Search API endpoints, context hashes, user IDs (e.g. 0x22B1, /orders)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-transparent pl-10 pr-10 py-1 text-sm text-slate-100 placeholder-slate-500 focus:outline-none font-mono"
          />
          <button onClick={onClose} className="p-1 text-slate-400 hover:text-slate-100">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Search Results */}
        <div className="space-y-1.5 max-h-80 overflow-y-auto">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block px-2">
            {query.trim() ? `Search Results (${results.length})` : 'Recent Telemetry Logs'}
          </span>

          {results.map((log) => (
            <div
              key={log.id}
              onClick={() => {
                onSelectLog(log);
                onClose();
              }}
              className="p-3 rounded-xl bg-slate-950 hover:bg-slate-800/80 border border-slate-800/80 transition-all cursor-pointer flex items-center justify-between group font-mono text-xs"
            >
              <div className="space-y-1 overflow-hidden pr-2">
                <div className="flex items-center gap-2">
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-900 border border-slate-700 text-blue-400">
                    {log.method}
                  </span>
                  <span className="text-slate-200 font-semibold truncate">{log.endpoint}</span>
                </div>
                <div className="flex items-center gap-3 text-[10px] text-slate-400">
                  <span>User: {log.userId}</span>
                  <span>Hash: <code className="text-blue-300">{log.contextHash}</code></span>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {log.status === 'BLOCKED' ? (
                  <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[10px] font-bold">
                    BLOCKED ({log.threatType})
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px]">
                    ALLOWED
                  </span>
                )}
                <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-slate-200 transition-colors" />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
