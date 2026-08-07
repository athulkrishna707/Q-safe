import React, { useState } from 'react';
import { CCFH_WORKFLOW_NODES } from '../data/mockData';
import { CCFHNode } from '../types';
import {
  GitBranch,
  Lock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ArrowRight,
  Code2,
  ShieldCheck,
} from 'lucide-react';

interface SequenceVisualizerProps {
  onSimulateSequenceAttack?: () => void;
}

export const SequenceVisualizer: React.FC<SequenceVisualizerProps> = ({ onSimulateSequenceAttack }) => {
  const [activePreset, setActivePreset] = useState<'VALID' | 'ATTACK_SEQUENCE' | 'ATTACK_BOLA'>('VALID');
  const [selectedNode, setSelectedNode] = useState<CCFHNode | null>(CCFH_WORKFLOW_NODES[2]);

  // Generate node sequence based on active preset
  const getNodes = () => {
    if (activePreset === 'VALID') {
      return CCFH_WORKFLOW_NODES.map((n) => ({ ...n, status: 'valid' as const }));
    } else if (activePreset === 'ATTACK_SEQUENCE') {
      return CCFH_WORKFLOW_NODES.map((n, idx) => {
        if (idx < 3) return { ...n, status: 'valid' as const };
        if (idx === 3)
          return {
            ...n,
            label: '3b. Skipped OTP!',
            status: 'invalid' as const,
            hash: '0xEE41 (SKEW)',
            description: 'Attacker attempted to skip hardware OTP verification step!',
          };
        return {
          ...n,
          label: '4. Execute Aborted',
          status: 'invalid' as const,
          hash: '0x0000',
          description: 'Q-SAFE CCFH Engine intercepted transfer execution due to invalid hash sequence.',
        };
      });
    } else {
      // BOLA preset
      return CCFH_WORKFLOW_NODES.map((n, idx) => {
        if (idx === 0) return { ...n, status: 'valid' as const };
        if (idx === 1)
          return {
            ...n,
            endpoint: '/api/v1/orders/99/refund',
            hash: '0x22B1',
            status: 'invalid' as const,
            label: 'Direct Refund Jump',
            description: 'Direct call to order refund resource owned by another tenant.',
          };
        return {
          ...n,
          status: 'invalid' as const,
          label: `Step ${idx + 1} Blocked`,
        };
      });
    }
  };

  const currentNodes = getNodes();

  return (
    <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl space-y-4">
      {/* Visualizer Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400">
            <GitBranch className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2 font-mono">
              Sequence Integrity Engine
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20 font-sans font-medium">
                CCFH Graph
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Contextual Control Flow Hashing state transition validation and rolling entropy proof
            </p>
          </div>
        </div>

        {/* Preset Flow Switcher Buttons */}
        <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-mono">
          <button
            onClick={() => setActivePreset('VALID')}
            className={`px-3 py-1.5 rounded-md font-medium transition-all ${
              activePreset === 'VALID'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Valid Lineage Flow
          </button>
          <button
            onClick={() => setActivePreset('ATTACK_SEQUENCE')}
            className={`px-3 py-1.5 rounded-md font-medium transition-all ${
              activePreset === 'ATTACK_SEQUENCE'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            OTP Bypass Skew Attack
          </button>
          <button
            onClick={() => setActivePreset('ATTACK_BOLA')}
            className={`px-3 py-1.5 rounded-md font-medium transition-all ${
              activePreset === 'ATTACK_BOLA'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            BOLA Direct Jump
          </button>
        </div>
      </div>

      {/* Horizontal Step Graph Visualizer */}
      <div className="py-4 overflow-x-auto">
        <div className="flex items-center justify-between min-w-[760px] gap-2 px-2">
          {currentNodes.map((node, index) => {
            const isSelected = selectedNode?.id === node.id;
            const isValid = node.status === 'valid';
            const isLast = index === currentNodes.length - 1;

            return (
              <React.Fragment key={node.id}>
                {/* Node Step Card */}
                <div
                  onClick={() => setSelectedNode(node)}
                  className={`flex-1 min-w-[130px] p-3 rounded-xl border transition-all duration-200 cursor-pointer relative group ${
                    isSelected
                      ? isValid
                        ? 'bg-blue-950/40 border-blue-500 text-slate-100 shadow-lg shadow-blue-950/50 scale-105'
                        : 'bg-rose-950/40 border-rose-500 text-slate-100 shadow-lg shadow-rose-950/50 scale-105'
                      : isValid
                      ? 'bg-slate-950/80 hover:bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700'
                      : 'bg-rose-950/20 border-rose-500/40 text-rose-300 hover:bg-rose-950/30'
                  }`}
                >
                  {/* Step Header Badge */}
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                      Step {node.stepIndex}
                    </span>
                    {isValid ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-400 animate-pulse" />
                    )}
                  </div>

                  {/* Node Label & Endpoint */}
                  <div className="space-y-1">
                    <h4 className="text-xs font-semibold text-slate-100 font-mono truncate">
                      {node.label}
                    </h4>
                    <p className="text-[10px] font-mono text-slate-400 truncate">
                      {node.endpoint}
                    </p>
                  </div>

                  {/* Rolling Hash pill */}
                  <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between">
                    <span className="text-[10px] text-slate-500 font-mono">Hash:</span>
                    <span
                      className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                        isValid
                          ? 'bg-blue-500/10 text-blue-300 border border-blue-500/20'
                          : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                      }`}
                    >
                      {node.hash}
                    </span>
                  </div>

                  {/* Attack Warning Tooltip callout on invalid node */}
                  {!isValid && (
                    <div className="absolute -top-9 left-1/2 -translate-x-1/2 px-2.5 py-1 rounded bg-rose-600 text-white font-mono text-[10px] font-bold shadow-lg whitespace-nowrap z-20 flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3 text-white" />
                      Invalid Context Hash!
                    </div>
                  )}
                </div>

                {/* Connector Arrow & Math Formula */}
                {!isLast && (
                  <div className="flex flex-col items-center justify-center shrink-0 text-slate-600 px-1 font-mono text-[9px]">
                    <span className="text-slate-500 font-medium">Shift & XOR</span>
                    <ArrowRight
                      className={`w-4 h-4 ${
                        isValid ? 'text-blue-400' : 'text-rose-500'
                      }`}
                    />
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Selected Node Rolling Hash Math & Technical Explanation */}
      {selectedNode && (
        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/90 grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
          {/* Left: Math Equation */}
          <div className="space-y-1.5">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider flex items-center gap-1">
              <Code2 className="w-3.5 h-3.5 text-blue-400" />
              Rolling Hash Equation (CCFH)
            </span>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-blue-300 font-bold text-xs">
              <code>
                H_{selectedNode.stepIndex} = (H_{selectedNode.stepIndex - 1} &lt;&lt; 1) ^ Hash(
                {selectedNode.endpoint})
              </code>
            </div>
            <p className="text-[10px] text-slate-500 font-sans">
              Bitwise left-shift & bitwise XOR injects current route payload context into the cryptographic session chain.
            </p>
          </div>

          {/* Middle: Active Node Status */}
          <div className="space-y-1.5">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider flex items-center gap-1">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              Role Authorization Constraint
            </span>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-200">
              <span className="text-slate-400 text-[10px]">Required Claim: </span>
              <span className="text-emerald-400 font-semibold">{selectedNode.requiredRole}</span>
            </div>
            <p className="text-[10px] text-slate-500 font-sans">{selectedNode.description}</p>
          </div>

          {/* Right: State Integrity Verdict */}
          <div className="space-y-1.5">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              Gateway Verification State
            </span>
            <div
              className={`p-2.5 rounded-lg border font-semibold flex items-center justify-between ${
                selectedNode.status === 'valid'
                  ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                  : 'bg-rose-500/10 text-rose-300 border-rose-500/30'
              }`}
            >
              <span>{selectedNode.status === 'valid' ? 'LINEAGE VERIFIED' : 'SEQUENCE MISMATCH'}</span>
              <span className="text-[10px]">{selectedNode.hash}</span>
            </div>
            <p className="text-[10px] text-slate-500 font-sans">
              {selectedNode.status === 'valid'
                ? 'Linear state progression matches gateway policy matrix.'
                : 'Sequence anomaly detected: Request blocked before reaching controller.'}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
