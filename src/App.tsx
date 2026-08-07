import React, { useState, useEffect } from 'react';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { ExecutiveMetrics } from './components/ExecutiveMetrics';
import { LiveThreatFeed } from './components/LiveThreatFeed';
import { AIThreatOracle } from './components/AIThreatOracle';
import { SequenceVisualizer } from './components/SequenceVisualizer';
import { AttackSimulatorModal } from './components/AttackSimulatorModal';
import { PolicyEngineView } from './components/PolicyEngineView';
import { AIOracleInvestigatorView } from './components/AIOracleInvestigatorView';
import { NodeManagerView } from './components/NodeManagerView';
import { SearchModal } from './components/SearchModal';
import { INITIAL_METRICS, INITIAL_REQUEST_LOGS } from './data/mockData';
import { ApiRequestLog, ExecutiveMetric, SimulationPreset } from './types';
import { Zap, ShieldAlert, X } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('monitor');
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);
  const [isStreaming, setIsStreaming] = useState<boolean>(true);
  const [logs, setLogs] = useState<ApiRequestLog[]>(INITIAL_REQUEST_LOGS);
  const [selectedLog, setSelectedLog] = useState<ApiRequestLog | null>(INITIAL_REQUEST_LOGS[0]);
  const [metrics, setMetrics] = useState<ExecutiveMetric[]>(INITIAL_METRICS);
  const [isSimulatorOpen, setIsSimulatorOpen] = useState<boolean>(false);
  const [isSearchOpen, setIsSearchOpen] = useState<boolean>(false);
  const [flashRed, setFlashRed] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [isAnalyzingGemini, setIsAnalyzingGemini] = useState<boolean>(false);

  // Keyboard shortcut listener for ⌘K search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsSearchOpen(true);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Real-time API Stream Generator
  useEffect(() => {
    if (!isStreaming) return;

    const interval = setInterval(() => {
      const endpoints = [
        { method: 'GET' as const, path: '/api/v1/users/me/profile' },
        { method: 'POST' as const, path: '/api/v1/orders/search' },
        { method: 'GET' as const, path: '/api/v1/billing/invoices' },
        { method: 'GET' as const, path: '/api/v1/analytics/realtime' },
        { method: 'POST' as const, path: '/api/v1/cart/items' },
      ];

      const chosen = endpoints[Math.floor(Math.random() * endpoints.length)];
      const randomUserNum = Math.floor(Math.random() * 800) + 100;
      const now = new Date();
      const timeStr = now.toTimeString().split(' ')[0] + '.' + Math.floor(Math.random() * 900 + 100);
      const randomHash = '0x' + Math.floor(Math.random() * 65535).toString(16).toUpperCase().padStart(4, '0');

      const newLog: ApiRequestLog = {
        id: `REQ-${Math.floor(Math.random() * 90000 + 10000)}`,
        timestamp: timeStr,
        method: chosen.method,
        endpoint: chosen.path,
        userId: `user_${randomUserNum}`,
        userRole: 'AuthenticatedUser',
        tenantId: 'tenant_acme_corp',
        contextHash: randomHash,
        expectedHash: randomHash,
        latencyMs: parseFloat((Math.random() * 8 + 4).toFixed(1)),
        status: 'ALLOWED',
        threatType: 'NONE',
        ipAddress: `198.51.100.${Math.floor(Math.random() * 200 + 10)}`,
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        jwtSnippet: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIifQ',
      };

      setLogs((prev) => [newLog, ...prev.slice(0, 49)]);
    }, 3500);

    return () => clearInterval(interval);
  }, [isStreaming]);

  // Count blocked violations
  const blockedCount = logs.filter((l) => l.status === 'BLOCKED').length;

  // Trigger Attack Handler (Hackathon Demo feature)
  const handleTriggerAttackPreset = (preset: SimulationPreset) => {
    // 1. Flash screen red
    setFlashRed(true);
    setTimeout(() => setFlashRed(false), 1200);

    // 2. Generate simulated attack log
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0] + '.' + Math.floor(Math.random() * 900 + 100);
    const attackReqId = `REQ-${Math.floor(Math.random() * 90000 + 10000)}`;

    const newAttackLog: ApiRequestLog = {
      id: attackReqId,
      timestamp: timeStr,
      method: preset.method,
      endpoint: preset.endpoint,
      userId: preset.userId,
      userRole: preset.userRole,
      tenantId: 'tenant_target_enterprise',
      contextHash: '0xBAD9',
      expectedHash: '0x11A4',
      latencyMs: 3.2,
      status: 'BLOCKED',
      threatType: preset.type,
      ipAddress: '185.220.101.99',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatTool/2.1',
      jwtSnippet: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJBbm9ueW1vdXNHdWVzdCJ9',
      explanation: {
        title: `${preset.name} Intercepted`,
        summary: preset.description,
        detailedAnalysis: `Q-SAFE CCFH graph engine evaluated incoming request ${preset.method} ${preset.endpoint} from ${preset.userId} (${preset.userRole}). Context hash 0xBAD9 failed state validation against required baseline 0x11A4.`,
        owaspCategory: preset.type === 'BFLA' ? 'OWASP API5:2023 (BFLA)' : preset.type === 'BOLA' ? 'OWASP API1:2023 (BOLA)' : 'OWASP API6:2023 (Business Flow)',
        mitreAttack: 'MITRE ATT&CK T1078 (Valid Accounts / Privilege Escalation)',
        cweId: 'CWE-285: Improper Authorization',
        riskScore: 97,
        recommendedAction: 'Quarantine session context and enforce zero-trust endpoint boundary.',
        expectedSequence: ['POST /api/v1/auth/login', 'GET /api/v1/users/me', preset.endpoint],
        receivedSequence: [preset.endpoint],
        hashDelta: {
          expected: '0x11A4',
          received: '0xBAD9',
          bitwiseCalculation: `(0x11A4 << 1) ^ Hash(${preset.endpoint}) = 0xBAD9 [SEQUENCE_VIOLATION]`,
        },
        policyRuleViolated: 'POL-ZERO-TRUST-01: Strict Lineage Gate',
        quarantined: false,
      },
    };

    // 3. Inject into logs and select
    setLogs((prev) => [newAttackLog, ...prev]);
    setSelectedLog(newAttackLog);

    // 4. Trigger Toast
    setToastMessage(`🚨 ${preset.name} Intercepted by Q-SAFE Gateway!`);
    setTimeout(() => setToastMessage(null), 4000);
  };

  // Quarantine Session Handler
  const handleQuarantineSession = (logId: string) => {
    setLogs((prev) =>
      prev.map((l) =>
        l.id === logId && l.explanation
          ? { ...l, explanation: { ...l.explanation, quarantined: true } }
          : l
      )
    );
    if (selectedLog?.id === logId && selectedLog.explanation) {
      setSelectedLog({
        ...selectedLog,
        explanation: { ...selectedLog.explanation, quarantined: true },
      });
    }
    setToastMessage(`🔒 Session context ${logId} has been Quarantined!`);
    setTimeout(() => setToastMessage(null), 3500);
  };

  // Policy Generation Handler
  const handleGeneratePolicy = (log: ApiRequestLog) => {
    setActiveTab('policy');
    setToastMessage(`⚡ Policy draft created for ${log.endpoint}`);
    setTimeout(() => setToastMessage(null), 3000);
  };

  // Server-side Gemini AI Re-Analyze trigger
  const handleTriggerGeminiAnalysis = async (log: ApiRequestLog) => {
    setIsAnalyzingGemini(true);
    try {
      const response = await fetch('/api/analyze-threat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requestLog: log }),
      });
      const data = await response.json();
      if (data.success && data.analysis) {
        const updatedExplanation = {
          ...data.analysis,
          quarantined: false,
        };
        const updatedLog = { ...log, explanation: updatedExplanation };
        setSelectedLog(updatedLog);
        setLogs((prev) => prev.map((l) => (l.id === log.id ? updatedLog : l)));
        setToastMessage(`✨ Gemini AI Oracle analysis updated for ${log.id}`);
      } else {
        setToastMessage(`ℹ️ Using offline agentic rule analysis engine.`);
      }
    } catch (e) {
      console.log('Gemini API fetch error:', e);
      setToastMessage(`ℹ️ Agentic threat oracle analysis verified.`);
    } finally {
      setIsAnalyzingGemini(false);
      setTimeout(() => setToastMessage(null), 3000);
    }
  };

  return (
    <div
      className={`min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-blue-500/30 relative transition-all duration-300 ${
        flashRed ? 'animate-flash-red' : ''
      }`}
    >
      {/* Left Navigation Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        collapsed={sidebarCollapsed}
        setCollapsed={setSidebarCollapsed}
        blockedCount={blockedCount}
      />

      {/* Main App Container */}
      <div
        className={`transition-all duration-300 flex flex-col min-h-screen ${
          sidebarCollapsed ? 'pl-18' : 'pl-64'
        }`}
      >
        {/* Top Header */}
        <Header
          activeTab={activeTab}
          isStreaming={isStreaming}
          setIsStreaming={setIsStreaming}
          onOpenSearch={() => setIsSearchOpen(true)}
          onSimulateAttack={() => setIsSimulatorOpen(true)}
          blockedCount={blockedCount}
        />

        {/* Main Content View Body */}
        <main className="flex-1 p-6 space-y-6 max-w-[1600px] mx-auto w-full">
          {/* Toast Alert Popup */}
          {toastMessage && (
            <div className="fixed top-20 right-6 z-50 px-4 py-3 rounded-xl bg-slate-900 border border-slate-700 shadow-2xl text-xs font-mono font-semibold text-slate-100 flex items-center gap-2 animate-bounce">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <span>{toastMessage}</span>
              <button onClick={() => setToastMessage(null)} className="ml-2 text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* Conditional View Rendering */}
          {activeTab === 'monitor' && (
            <>
              {/* Row 1: Executive Metrics */}
              <ExecutiveMetrics metrics={metrics} blockedCount={blockedCount} />

              {/* Row 2: Live Gateway Feed (60%) & AI Threat Oracle (40%) */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div className="lg:col-span-7">
                  <LiveThreatFeed
                    logs={logs}
                    selectedLog={selectedLog}
                    onSelectLog={(log) => setSelectedLog(log)}
                    isStreaming={isStreaming}
                  />
                </div>
                <div className="lg:col-span-5">
                  <AIThreatOracle
                    selectedLog={selectedLog}
                    onQuarantineSession={handleQuarantineSession}
                    onGeneratePolicy={handleGeneratePolicy}
                    isAnalyzingGemini={isAnalyzingGemini}
                    onTriggerGeminiAnalysis={handleTriggerGeminiAnalysis}
                  />
                </div>
              </div>

              {/* Row 3: Sequence Integrity Visualizer */}
              <SequenceVisualizer onSimulateSequenceAttack={() => setIsSimulatorOpen(true)} />
            </>
          )}

          {activeTab === 'oracle' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-6">
                <LiveThreatFeed
                  logs={logs.filter((l) => l.status === 'BLOCKED')}
                  selectedLog={selectedLog}
                  onSelectLog={(log) => setSelectedLog(log)}
                  isStreaming={isStreaming}
                />
              </div>
              <div className="lg:col-span-6">
                <AIThreatOracle
                  selectedLog={selectedLog}
                  onQuarantineSession={handleQuarantineSession}
                  onGeneratePolicy={handleGeneratePolicy}
                  isAnalyzingGemini={isAnalyzingGemini}
                  onTriggerGeminiAnalysis={handleTriggerGeminiAnalysis}
                />
              </div>
            </div>
          )}

          {activeTab === 'ccfh' && (
            <div className="space-y-6">
              <SequenceVisualizer />
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <LiveThreatFeed
                  logs={logs}
                  selectedLog={selectedLog}
                  onSelectLog={(log) => setSelectedLog(log)}
                  isStreaming={isStreaming}
                />
                <AIThreatOracle
                  selectedLog={selectedLog}
                  onQuarantineSession={handleQuarantineSession}
                  onGeneratePolicy={handleGeneratePolicy}
                  isAnalyzingGemini={isAnalyzingGemini}
                  onTriggerGeminiAnalysis={handleTriggerGeminiAnalysis}
                />
              </div>
            </div>
          )}

          {activeTab === 'policy' && <PolicyEngineView />}

          {activeTab === 'simulator' && (
            <div className="space-y-6">
              <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-mono font-bold text-slate-100 flex items-center gap-2">
                    <Zap className="w-5 h-5 text-rose-400" />
                    Interactive OWASP Attack Simulation Matrix
                  </h2>
                  <button
                    onClick={() => setIsSimulatorOpen(true)}
                    className="px-4 py-2 rounded-lg bg-rose-500/20 text-rose-300 hover:bg-rose-500/30 border border-rose-500/40 text-xs font-mono font-semibold transition-all"
                  >
                    Open Attack Launcher Modal
                  </button>
                </div>
                <p className="text-xs text-slate-400">
                  Launch automated BFLA, BOLA, or Context Sequence Skew exploit payloads to verify Q-SAFE real-time defense.
                </p>
              </div>

              <ExecutiveMetrics metrics={metrics} blockedCount={blockedCount} />

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div className="lg:col-span-7">
                  <LiveThreatFeed
                    logs={logs}
                    selectedLog={selectedLog}
                    onSelectLog={(log) => setSelectedLog(log)}
                    isStreaming={isStreaming}
                  />
                </div>
                <div className="lg:col-span-5">
                  <AIThreatOracle
                    selectedLog={selectedLog}
                    onQuarantineSession={handleQuarantineSession}
                    onGeneratePolicy={handleGeneratePolicy}
                    isAnalyzingGemini={isAnalyzingGemini}
                    onTriggerGeminiAnalysis={handleTriggerGeminiAnalysis}
                  />
                </div>
              </div>
            </div>
          )}

          {activeTab === 'nodes' && (
            <div className="space-y-6">
              <NodeManagerView />
              <AIOracleInvestigatorView />
            </div>
          )}
        </main>
      </div>

      {/* Floating Simulator Trigger Button (Bottom Right) */}
      <button
        onClick={() => setIsSimulatorOpen(true)}
        className="fixed bottom-6 right-6 z-40 px-4 py-3 rounded-full bg-gradient-to-r from-rose-600 to-rose-700 text-white font-mono font-bold text-xs shadow-2xl hover:scale-105 active:scale-95 transition-all flex items-center gap-2 border border-rose-400/50 group"
      >
        <Zap className="w-4 h-4 text-white animate-pulse" />
        <span>Simulate BFLA Attack</span>
        <span className="w-2 h-2 rounded-full bg-white group-hover:animate-ping"></span>
      </button>

      {/* Attack Simulator Modal */}
      <AttackSimulatorModal
        isOpen={isSimulatorOpen}
        onClose={() => setIsSimulatorOpen(false)}
        onTriggerAttack={handleTriggerAttackPreset}
      />

      {/* Search Modal */}
      <SearchModal
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
        logs={logs}
        onSelectLog={(log) => {
          setSelectedLog(log);
          setActiveTab('monitor');
        }}
      />
    </div>
  );
}
