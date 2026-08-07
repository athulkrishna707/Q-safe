import React, { useState } from 'react';
import { ApiRequestLog, ThreatExplanation } from '../types';
import {
  Brain,
  ShieldAlert,
  ShieldCheck,
  Tag,
  AlertTriangle,
  Lock,
  FileCode,
  Copy,
  Check,
  UserX,
  Sparkles,
  RefreshCcw,
} from 'lucide-react';

interface AIThreatOracleProps {
  selectedLog: ApiRequestLog | null;
  onQuarantineSession: (logId: string) => void;
  onGeneratePolicy: (log: ApiRequestLog) => void;
  isAnalyzingGemini?: boolean;
  onTriggerGeminiAnalysis?: (log: ApiRequestLog) => void;
}

export const AIThreatOracle: React.FC<AIThreatOracleProps> = ({
  selectedLog,
  onQuarantineSession,
  onGeneratePolicy,
  isAnalyzingGemini = false,
  onTriggerGeminiAnalysis,
}) => {
  const [copiedPayload, setCopiedPayload] = useState(false);

  if (!selectedLog) {
    return (
      <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-8 flex flex-col items-center justify-center text-center h-[520px]">
        <div className="w-12 h-12 rounded-xl bg-slate-800/80 border border-slate-700 flex items-center justify-center text-blue-400 mb-3 shadow-lg">
          <Brain className="w-6 h-6 animate-pulse" />
        </div>
        <h3 className="text-sm font-semibold text-slate-200 font-mono">
          Agentic AI Threat Oracle
        </h3>
        <p className="text-xs text-slate-400 mt-1 max-w-xs">
          Select any request row from the Live Feed to view deep agentic explainability and forensic lineage.
        </p>
      </div>
    );
  }

  const isBlocked = selectedLog.status === 'BLOCKED';
  const explanation: ThreatExplanation | undefined = selectedLog.explanation;

  const handleCopyForensics = () => {
    const payload = JSON.stringify(selectedLog, null, 2);
    navigator.clipboard.writeText(payload);
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 1500);
  };

  return (
    <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl flex flex-col h-[520px] overflow-hidden shadow-xl">
      {/* Top Oracle Header */}
      <div className="p-4 border-b border-slate-800/80 bg-slate-950/80 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400 shadow-inner">
            <Brain className="w-4 h-4 text-blue-400" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2 font-mono">
              Agentic AI Analysis
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-sans font-medium">
                {selectedLog.id}
              </span>
            </h2>
            <p className="text-[11px] text-slate-400 font-mono truncate">
              {selectedLog.method} {selectedLog.endpoint}
            </p>
          </div>
        </div>

        {/* Status / Risk score pill */}
        <div className="flex items-center gap-2">
          {isBlocked ? (
            <span className="px-2.5 py-1 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[11px] font-mono font-bold flex items-center gap-1">
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
              CRITICAL RISK ({explanation?.riskScore || 94}/100)
            </span>
          ) : (
            <span className="px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[11px] font-mono font-semibold flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              BASELINE SECURE
            </span>
          )}
        </div>
      </div>

      {/* Main Content Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
        {/* Plain English Explanation */}
        <div className={`p-3.5 rounded-xl border ${isBlocked ? 'bg-rose-950/20 border-rose-500/30 text-rose-200' : 'bg-slate-950/60 border-slate-800 text-slate-300'}`}>
          <div className="flex items-center justify-between font-mono font-bold text-xs mb-1.5 text-slate-100">
            <span className="flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-blue-400" />
              {explanation?.title || 'Gateway Request Inspection'}
            </span>
            {explanation?.quarantined && (
              <span className="text-[10px] px-2 py-0.5 rounded bg-rose-900/80 text-rose-200 border border-rose-700 font-mono uppercase font-bold animate-pulse">
                QUARANTINED
              </span>
            )}
          </div>
          <p className="text-xs leading-relaxed text-slate-300 font-sans">
            {explanation?.summary ||
              `Request allowed under active Zero-Trust Policy rules. Context hash ${selectedLog.contextHash} matches expected baseline state.`}
          </p>

          {explanation?.detailedAnalysis && (
            <div className="mt-2.5 pt-2.5 border-t border-rose-500/20 text-[11px] text-slate-300 space-y-1 font-mono">
              <span className="text-slate-400 font-medium">Forensic Breakdown:</span>
              <p className="font-sans leading-relaxed text-slate-300">
                {explanation.detailedAnalysis}
              </p>
            </div>
          )}
        </div>

        {/* OWASP & MITRE ATT&CK Tags */}
        {explanation && (
          <div className="space-y-1.5">
            <span className="text-[10px] font-mono font-semibold text-slate-400 uppercase tracking-wider">
              Security Mapping & Context
            </span>
            <div className="flex flex-wrap gap-1.5">
              <span className="px-2.5 py-1 rounded-md bg-rose-500/10 text-rose-300 border border-rose-500/30 text-[11px] font-mono font-medium flex items-center gap-1">
                <Tag className="w-3 h-3 text-rose-400" />
                {explanation.owaspCategory}
              </span>
              <span className="px-2.5 py-1 rounded-md bg-blue-500/10 text-blue-300 border border-blue-500/30 text-[11px] font-mono font-medium flex items-center gap-1">
                <AlertTriangle className="w-3 h-3 text-blue-400" />
                {explanation.mitreAttack}
              </span>
              <span className="px-2.5 py-1 rounded-md bg-slate-800 text-slate-300 border border-slate-700 text-[11px] font-mono">
                {explanation.cweId}
              </span>
            </div>
          </div>
        )}

        {/* Bitwise Context Hash Delta Visualizer */}
        {explanation?.hashDelta && (
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2 font-mono text-[11px]">
            <div className="flex items-center justify-between text-slate-400 border-b border-slate-800/80 pb-1.5">
              <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-blue-400" />
                Rolling Context Hash (CCFH) Proof
              </span>
              <span className="text-[10px] text-rose-400 font-semibold">MISMATCH</span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <span className="text-[10px] text-slate-400 block">Expected Hash</span>
                <span className="text-emerald-400 font-bold">{explanation.hashDelta.expected}</span>
              </div>
              <div className="p-2 rounded bg-rose-950/40 border border-rose-500/30">
                <span className="text-[10px] text-slate-400 block">Received Hash</span>
                <span className="text-rose-400 font-bold">{explanation.hashDelta.received}</span>
              </div>
            </div>

            <div className="p-2 rounded bg-slate-900/80 border border-slate-800 text-[10px] text-slate-300 font-mono overflow-x-auto">
              <span className="text-slate-400">Bitwise Equation: </span>
              <code className="text-blue-300">{explanation.hashDelta.bitwiseCalculation}</code>
            </div>
          </div>
        )}

        {/* User Claims & JWT Snippet */}
        <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2 font-mono text-[11px]">
          <div className="flex items-center justify-between text-slate-400 border-b border-slate-800/80 pb-1">
            <span className="font-semibold text-slate-300">User Identity & JWT Token Claims</span>
            <span className="text-slate-500 text-[10px]">{selectedLog.ipAddress}</span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-[11px]">
            <div>
              <span className="text-slate-500 text-[10px]">Subject ID:</span>
              <span className="text-slate-200 block font-medium">{selectedLog.userId}</span>
            </div>
            <div>
              <span className="text-slate-500 text-[10px]">Role / Tenant:</span>
              <span className="text-slate-200 block font-medium">
                {selectedLog.userRole} ({selectedLog.tenantId})
              </span>
            </div>
          </div>

          <div className="p-2 rounded bg-slate-900 border border-slate-800 text-[10px] text-slate-400 break-all">
            <span className="text-slate-500">JWT Token Snippet:</span>
            <div className="text-blue-300/80 mt-0.5 truncate">{selectedLog.jwtSnippet}</div>
          </div>
        </div>
      </div>

      {/* Action Buttons Bar Footer */}
      <div className="p-3 border-t border-slate-800 bg-slate-950/90 flex flex-wrap items-center justify-between gap-2">
        {isBlocked ? (
          <button
            onClick={() => onQuarantineSession(selectedLog.id)}
            disabled={explanation?.quarantined}
            className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold font-mono border transition-all ${
              explanation?.quarantined
                ? 'bg-slate-800 text-slate-400 border-slate-700 cursor-not-allowed'
                : 'bg-rose-500/20 text-rose-300 hover:bg-rose-500/30 border-rose-500/40 shadow-sm'
            }`}
          >
            <UserX className="w-3.5 h-3.5" />
            {explanation?.quarantined ? 'Session Quarantined' : 'Quarantine Session'}
          </button>
        ) : (
          <button
            onClick={() => onGeneratePolicy(selectedLog)}
            className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold font-mono bg-blue-500/20 text-blue-300 hover:bg-blue-500/30 border border-blue-500/40 transition-all"
          >
            <FileCode className="w-3.5 h-3.5" />
            Generate Policy Rule
          </button>
        )}

        <button
          onClick={handleCopyForensics}
          className="flex items-center gap-1 px-3 py-2 rounded-lg text-xs font-mono font-medium bg-slate-900 text-slate-300 hover:text-slate-100 hover:bg-slate-800 border border-slate-800 transition-all"
          title="Export forensic JSON payload"
        >
          {copiedPayload ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span>Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5" />
              <span>Export</span>
            </>
          )}
        </button>

        {onTriggerGeminiAnalysis && (
          <button
            onClick={() => onTriggerGeminiAnalysis(selectedLog)}
            disabled={isAnalyzingGemini}
            className="p-2 rounded-lg text-xs font-mono bg-slate-900 text-blue-400 hover:bg-slate-800 border border-slate-800 transition-all flex items-center gap-1"
            title="Re-run deep AI agentic analysis"
          >
            <RefreshCcw className={`w-3.5 h-3.5 ${isAnalyzingGemini ? 'animate-spin text-blue-400' : ''}`} />
          </button>
        )}
      </div>
    </div>
  );
};
