import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Route for Gemini Threat Oracle dynamic analysis
  app.post('/api/analyze-threat', async (req, res) => {
    try {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) {
        return res.status(200).json({
          success: false,
          message: 'No GEMINI_API_KEY set, using fallback simulated analysis.',
        });
      }

      const ai = new GoogleGenAI({ apiKey });
      const { requestLog } = req.body;

      const prompt = `You are the Q-SAFE AI Threat Oracle, an expert Zero-Trust API Security Gateway Engine.
Analyze this blocked API request:
- ID: ${requestLog?.id}
- Endpoint: ${requestLog?.endpoint}
- Method: ${requestLog?.method}
- User: ${requestLog?.userId} (Role: ${requestLog?.userRole}, Tenant: ${requestLog?.tenantId})
- Received Context Hash: ${requestLog?.contextHash} (Expected: ${requestLog?.expectedHash})
- Identified Threat Type: ${requestLog?.threatType}

Return a valid JSON object strictly adhering to this schema:
{
  "title": "Short title describing the threat intercepted",
  "summary": "1 plain-English sentence summarizing the violation",
  "detailedAnalysis": "2-3 technical sentences detailing the root cause, JWT claims context, and CCFH state sequence anomaly",
  "owaspCategory": "e.g. OWASP API1:2023 (BOLA) or OWASP API5:2023 (BFLA)",
  "mitreAttack": "e.g. MITRE ATT&CK T1078 (Valid Accounts)",
  "cweId": "e.g. CWE-639: Authorization Bypass Through User-Controlled Key",
  "riskScore": 95,
  "recommendedAction": "Actionable security mitigation step",
  "expectedSequence": ["POST /api/v1/auth/login", "GET /api/v1/orders/me", "POST /api/v1/orders/99/refund"],
  "receivedSequence": ["POST /api/v1/auth/login", "POST /api/v1/orders/99/refund"],
  "hashDelta": {
    "expected": "${requestLog?.expectedHash || '0x11A4'}",
    "received": "${requestLog?.contextHash || '0x22B1'}",
    "bitwiseCalculation": "(0x11A4 << 1) ^ Hash(${requestLog?.endpoint}) = ${requestLog?.contextHash} [INVALID SEQUENCE]"
  },
  "policyRuleViolated": "POL-BOLA-09: Object Tenant Boundary Check"
}
Output raw JSON only. No markdown formatting.`;

      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt,
      });

      const text = response.text || '';
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return res.json({ success: true, analysis: parsed });
      }

      return res.json({ success: false, message: 'Could not parse AI response', raw: text });
    } catch (err: any) {
      console.error('Gemini Threat Analysis Error:', err);
      return res.status(200).json({ success: false, error: err.message });
    }
  });

  // Health check endpoint
  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', engine: 'Q-SAFE Gateway v2.4.0', time: new Date().toISOString() });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
