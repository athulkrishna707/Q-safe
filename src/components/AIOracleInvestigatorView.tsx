import React from 'react';
import { Brain, ShieldAlert, CheckCircle2 } from 'lucide-react';

export const AIOracleInvestigatorView: React.FC = () => {
  const owaspMatrix = [
    { code: 'API1:2023', name: 'Broken Object Level Authorization (BOLA)', status: 'PROTECTED', coverage: '100% (CCFH Tenancy Validation)' },
    { code: 'API2:2023', name: 'Broken Authentication', status: 'PROTECTED', coverage: '100% (JWT Lineage & Proof)' },
    { code: 'API3:2023', name: 'Broken Object Property Level Authorization', status: 'PROTECTED', coverage: '98% (Field-Level Schema Filtering)' },
    { code: 'API4:2023', name: 'Unrestricted Resource Consumption', status: 'PROTECTED', coverage: '100% (Adaptive Token Bucket)' },
    { code: 'API5:2023', name: 'Broken Function Level Authorization (BFLA)', status: 'PROTECTED', coverage: '100% (Privilege Matrix Gate)' },
    { code: 'API6:2023', name: 'Unrestricted Access to Business Flows', status: 'PROTECTED', coverage: '100% (CCFH Control Flow Hashing)' },
    { code: 'API7:2023', name: 'Server Side Request Forgery (SSRF)', status: 'PROTECTED', coverage: '95% (Egress Proxy Inspection)' },
    { code: 'API8:2023', name: 'Security Misconfiguration', status: 'PROTECTED', coverage: '100% (Continuous Policy Audit)' },
  ];

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 backdrop-blur-md space-y-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/30 text-blue-400">
            <Brain className="w-6 h-6 text-blue-400 animate-pulse" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100 font-mono">
              Agentic AI Threat Intelligence & OWASP Matrix
            </h2>
            <p className="text-xs text-slate-400">
              Q-SAFE Agentic Oracle runs real-time micro-inference on session state context, evaluating graph lineage against OWASP Top 10 API Security Risks.
            </p>
          </div>
        </div>
      </div>

      {/* OWASP Coverage Grid */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
        <h3 className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-emerald-400" />
          OWASP API Security Top 10 2023 Coverage Matrix
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
          {owaspMatrix.map((item) => (
            <div
              key={item.code}
              className="p-3.5 rounded-lg bg-slate-950 border border-slate-800/80 flex items-center justify-between hover:border-slate-700 transition-colors"
            >
              <div className="space-y-1">
                <span className="text-[10px] text-blue-400 font-bold px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 mr-2">
                  {item.code}
                </span>
                <span className="text-slate-200 font-medium">{item.name}</span>
                <span className="block text-[10px] text-slate-400">{item.coverage}</span>
              </div>
              <span className="px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold flex items-center gap-1 shrink-0">
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                {item.status}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
