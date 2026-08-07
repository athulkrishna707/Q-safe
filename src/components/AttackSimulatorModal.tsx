import React from 'react';
import { SIMULATION_PRESETS } from '../data/mockData';
import { SimulationPreset } from '../types';
import {
  Zap,
  ShieldAlert,
  X,
  ArrowRight,
  Sparkles,
} from 'lucide-react';

interface AttackSimulatorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onTriggerAttack: (preset: SimulationPreset) => void;
}

export const AttackSimulatorModal: React.FC<AttackSimulatorModalProps> = ({
  isOpen,
  onClose,
  onTriggerAttack,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 shadow-2xl relative space-y-5">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3 border-b border-slate-800 pb-4">
          <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 shadow-lg">
            <Zap className="w-6 h-6 text-rose-400 animate-pulse" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100 font-mono flex items-center gap-2">
              Q-SAFE Attack Simulator Sandbox
              <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30 font-sans">
                Demo Engine
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Select an OWASP API Top 10 attack scenario to test Q-SAFE Zero-Trust interception in real-time.
            </p>
          </div>
        </div>

        {/* Attack Presets Grid */}
        <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
          {SIMULATION_PRESETS.map((preset) => (
            <div
              key={preset.id}
              onClick={() => {
                onTriggerAttack(preset);
                onClose();
              }}
              className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 hover:border-rose-500/50 hover:bg-slate-900 transition-all duration-200 cursor-pointer group space-y-2 relative"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold font-mono text-slate-100 group-hover:text-rose-400 flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  {preset.name}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20 font-semibold">
                  {preset.type}
                </span>
              </div>

              <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
                <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-emerald-400 font-bold">
                  {preset.method}
                </span>
                <code className="text-slate-300">{preset.endpoint}</code>
              </div>

              <p className="text-xs text-slate-400 font-sans leading-relaxed">
                {preset.description}
              </p>

              <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span className="text-slate-500">As User: {preset.userId} ({preset.userRole})</span>
                <span className="text-rose-400 font-semibold flex items-center gap-1 group-hover:translate-x-1 transition-transform">
                  Fire Payload <ArrowRight className="w-3.5 h-3.5" />
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Footer info */}
        <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 flex items-center gap-2 text-[11px] text-slate-400 font-mono">
          <Sparkles className="w-4 h-4 text-blue-400 shrink-0" />
          <span>
            Executing a simulation triggers edge flash animations, updates executive metrics, and pushes real-time telemetry to the AI Oracle.
          </span>
        </div>
      </div>
    </div>
  );
};
