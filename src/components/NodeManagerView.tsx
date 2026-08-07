import React from 'react';
import { Server, Globe } from 'lucide-react';

export const NodeManagerView: React.FC = () => {
  const nodes = [
    {
      id: 'sgw-us-east-4a',
      region: 'us-east-1 (N. Virginia)',
      status: 'ONLINE',
      latency: '4.2ms',
      requestsPerSec: '2,840 rps',
      uptime: '99.998%',
      certExpiry: '284 Days (mTLS Valid)',
      ip: '198.51.100.12',
    },
    {
      id: 'sgw-eu-west-1b',
      region: 'eu-west-1 (Ireland)',
      status: 'ONLINE',
      latency: '6.1ms',
      requestsPerSec: '1,210 rps',
      uptime: '100%',
      certExpiry: '192 Days (mTLS Valid)',
      ip: '198.51.100.88',
    },
    {
      id: 'sgw-ap-se-1c',
      region: 'ap-southeast-1 (Singapore)',
      status: 'ONLINE',
      latency: '8.8ms',
      requestsPerSec: '890 rps',
      uptime: '99.995%',
      certExpiry: '310 Days (mTLS Valid)',
      ip: '203.0.113.44',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 backdrop-blur-md space-y-2">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-slate-800 border border-slate-700 text-emerald-400">
            <Server className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100 font-mono">
              Gateway Edge Proxy Nodes & Cluster Health
            </h2>
            <p className="text-xs text-slate-400">
              Distributed Zero-Trust proxy nodes enforcing CCFH context hashing and OPA policy evaluation at sub-15ms edge latency.
            </p>
          </div>
        </div>
      </div>

      {/* Nodes List */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {nodes.map((node) => (
          <div
            key={node.id}
            className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4 font-mono text-xs hover:border-slate-700 transition-colors"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <span className="font-bold text-slate-100 text-sm flex items-center gap-2">
                <Globe className="w-4 h-4 text-blue-400" />
                {node.id}
              </span>
              <span className="px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                {node.status}
              </span>
            </div>

            <div className="space-y-2 text-slate-300">
              <div className="flex justify-between">
                <span className="text-slate-400">Region:</span>
                <span className="text-slate-200">{node.region}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Mean Latency:</span>
                <span className="text-emerald-400 font-bold">{node.latency}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Throughput:</span>
                <span className="text-blue-300">{node.requestsPerSec}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Cluster Uptime:</span>
                <span className="text-slate-200">{node.uptime}</span>
              </div>
              <div className="flex justify-between pt-2 border-t border-slate-800 text-[11px]">
                <span className="text-slate-400">mTLS Cert:</span>
                <span className="text-slate-300">{node.certExpiry}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
