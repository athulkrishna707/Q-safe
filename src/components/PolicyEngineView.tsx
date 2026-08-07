import React, { useState } from 'react';
import { INITIAL_POLICIES } from '../data/mockData';
import { PolicyRule } from '../types';
import {
  Sliders,
  CheckCircle2,
  Plus,
  FileCode,
  Lock,
} from 'lucide-react';

export const PolicyEngineView: React.FC = () => {
  const [policies, setPolicies] = useState<PolicyRule[]>(INITIAL_POLICIES);
  const [selectedPolicy, setSelectedPolicy] = useState<PolicyRule>(INITIAL_POLICIES[0]);
  const [activeCodeTab, setActiveCodeTab] = useState<'JSON' | 'REGO' | 'QSAFE_DSL'>('REGO');

  const handleTogglePolicy = (policyId: string) => {
    setPolicies((prev) =>
      prev.map((p) =>
        p.id === policyId ? { ...p, status: p.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE' } : p
      )
    );
  };

  const getPolicyRegoCode = (policy: PolicyRule) => {
    return `# Q-SAFE Rego Authorization Policy
# Rule ID: ${policy.id}
package qsafe.authz.policies

default allow = false

# Validate Object Tenancy & Control Flow Hashing Lineage
allow {
    input.method == "POST"
    input.path == "${policy.endpointPattern}"
    input.claims.tenant_id == input.resource.owner_tenant
    
    # Verify CCFH Rolling Hash Sequence
    qsafe.ccfh.verify_hash(input.context_hash, input.expected_hash)
    
    # Enforce Role Authorization Matrix
    input.claims.role == "VerifiedCustomer"
}

# Audit & Violation Telemetry Generation
violation[msg] {
    not allow
    msg := sprintf("Authorization Violation on %v by user %v", [input.path, input.claims.sub])
}`;
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl bg-slate-900/80 border border-slate-800 backdrop-blur-md">
        <div>
          <h2 className="text-base font-bold text-slate-100 font-mono flex items-center gap-2">
            <Sliders className="w-5 h-5 text-emerald-400" />
            Zero-Trust Policy Matrix
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Configure declarative Open Policy Agent (OPA) / Rego authorization policies enforced at gateway edge proxy nodes.
          </p>
        </div>

        <button className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30 border border-emerald-500/40 text-xs font-mono font-semibold transition-all shrink-0">
          <Plus className="w-4 h-4" />
          Create New Policy Rule
        </button>
      </div>

      {/* Grid: Policy List (Left) vs Code Editor (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Policy List */}
        <div className="lg:col-span-6 space-y-3">
          <h3 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">
            Active Authorization Rules ({policies.length})
          </h3>

          <div className="space-y-2">
            {policies.map((p) => {
              const isSelected = selectedPolicy.id === p.id;
              const isActive = p.status === 'ACTIVE';

              return (
                <div
                  key={p.id}
                  onClick={() => setSelectedPolicy(p)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer space-y-2 ${
                    isSelected
                      ? 'bg-slate-800/90 border-blue-500 text-slate-100 shadow-lg'
                      : 'bg-slate-900/60 hover:bg-slate-900 border-slate-800 text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold font-mono text-slate-100 flex items-center gap-2">
                      <Lock className="w-3.5 h-3.5 text-blue-400" />
                      {p.name}
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-400">
                        {p.id}
                      </span>
                      {/* Toggle Button */}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleTogglePolicy(p.id);
                        }}
                        className={`w-9 h-5 rounded-full p-0.5 transition-colors relative ${
                          isActive ? 'bg-emerald-500' : 'bg-slate-800'
                        }`}
                        title={isActive ? 'Disable policy' : 'Enable policy'}
                      >
                        <div
                          className={`w-4 h-4 rounded-full bg-white shadow-md transform transition-transform ${
                            isActive ? 'translate-x-4' : 'translate-x-0'
                          }`}
                        />
                      </button>
                    </div>
                  </div>

                  <p className="text-xs text-slate-400 font-sans leading-relaxed">
                    {p.description}
                  </p>

                  <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
                    <span>Pattern: <code className="text-blue-300">{p.endpointPattern}</code></span>
                    <span className="text-rose-400 font-semibold">{p.violationsCount} Blocked</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Rego / JSON Code Editor Preview */}
        <div className="lg:col-span-6 bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-emerald-400" />
              <span className="font-semibold text-slate-200">
                Policy Editor: {selectedPolicy.id}
              </span>
            </div>

            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-md border border-slate-800 text-[11px]">
              {(['REGO', 'JSON', 'QSAFE_DSL'] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveCodeTab(tab)}
                  className={`px-2.5 py-1 rounded transition-colors ${
                    activeCodeTab === tab
                      ? 'bg-slate-800 text-blue-400 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>
          </div>

          <div className="flex-1 bg-slate-950 p-4 rounded-lg border border-slate-800/90 overflow-x-auto text-slate-300 text-[11px] leading-relaxed select-all">
            <pre>
              {activeCodeTab === 'REGO' && getPolicyRegoCode(selectedPolicy)}
              {activeCodeTab === 'JSON' &&
                JSON.stringify(
                  {
                    policy_id: selectedPolicy.id,
                    name: selectedPolicy.name,
                    enforcement: selectedPolicy.enforcement,
                    endpoints: selectedPolicy.endpointPattern.split(','),
                    ccfh_strict_mode: true,
                    tenancy_validation: 'MANDATORY',
                  },
                  null,
                  2
                )}
              {activeCodeTab === 'QSAFE_DSL' &&
                `POLICY ${selectedPolicy.id} {
  MATCH ENDPOINT "${selectedPolicy.endpointPattern}"
  ENFORCE CCFH_HASH_LINEAGE = STRICT
  ENFORCE OBJECT_TENANCY = CLAIM.tenant_id
  ACTION = ${selectedPolicy.enforcement}
}`}
            </pre>
          </div>

          <div className="flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800">
            <span>Compiler: OPA v0.62.0 (Zero Syntax Errors)</span>
            <span className="text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              Compiled & Deployed to Edge
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
