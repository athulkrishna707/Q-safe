export type ThreatType = 'NONE' | 'BOLA' | 'BFLA' | 'SEQUENCE_SKEW' | 'TOKEN_REPLAY' | 'EXCESSIVE_DATA';

export type RequestStatus = 'ALLOWED' | 'BLOCKED' | 'FLAGGED';

export interface ApiRequestLog {
  id: string;
  timestamp: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  endpoint: string;
  userId: string;
  userRole: string;
  tenantId: string;
  contextHash: string;
  expectedHash: string;
  latencyMs: number;
  status: RequestStatus;
  threatType: ThreatType;
  ipAddress: string;
  userAgent: string;
  jwtSnippet: string;
  explanation?: ThreatExplanation;
  sequenceStep?: number;
  sequenceTotal?: number;
}

export interface ThreatExplanation {
  title: string;
  summary: string;
  detailedAnalysis: string;
  owaspCategory: string;
  mitreAttack: string;
  cweId: string;
  riskScore: number; // 0 to 100
  recommendedAction: string;
  expectedSequence: string[];
  receivedSequence: string[];
  hashDelta: {
    expected: string;
    received: string;
    bitwiseCalculation: string;
  };
  policyRuleViolated: string;
  quarantined?: boolean;
}

export interface ExecutiveMetric {
  title: string;
  value: string;
  change: string;
  trend: 'up' | 'down' | 'neutral';
  color: 'emerald' | 'amber' | 'rose' | 'blue';
  badgeText?: string;
  sparklineData: number[];
}

export interface CCFHNode {
  id: string;
  label: string;
  endpoint: string;
  stepIndex: number;
  hash: string;
  status: 'valid' | 'invalid' | 'pending';
  requiredRole: string;
  description: string;
}

export interface PolicyRule {
  id: string;
  name: string;
  endpointPattern: string;
  type: 'CCFH_STRICT' | 'OBJECT_OWNERSHIP' | 'FUNCTION_LEVEL_AUTH' | 'RATE_LIMIT';
  enforcement: 'BLOCK' | 'LOG' | 'CHALLENGE';
  status: 'ACTIVE' | 'DISABLED';
  description: string;
  lastTriggered: string;
  violationsCount: number;
}

export interface SimulationPreset {
  id: string;
  name: string;
  type: ThreatType;
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  userId: string;
  userRole: string;
  description: string;
  expectedBehavior: string;
}
