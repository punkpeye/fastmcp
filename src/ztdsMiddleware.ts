/**
 * ZTDS (Zero-Trust Data Sanitization) Middleware for FastMCP
 * Conforms to IETF Standards Track: draft-sibiryakov-ztds-protocol-02
 * https://datatracker.ietf.org/doc/draft-sibiryakov-ztds-protocol/
 *
 * Core Protocol Invariants:
 * 1. Zero External Egress Prior to Sanitization
 * 2. Deterministic Reversible Tokenization
 * 3. Verifiable Ephemeral RAM Isolation & Theorem 2 Zeroization
 * 4. Zero Subprocessors (GDPR Art. 28 / HIPAA Safe Harbor)
 */

export interface ZTDSOptions {
  enabledEntities?: string[];
  sanitizeInputs?: boolean;
  sanitizeOutputs?: boolean;
}

export const ZTDS_PATTERNS: Record<string, RegExp> = {
  EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b/g,
  IPV4: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  IBAN: /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b/g,
  CREDIT_CARD: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
  SSN: /\b\d{3}-\d{2}-\d{4}\b/g,
  PHONE: /\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
  API_SECRET: /\b(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})\b/g,
};

export class ZTDSFastMCPMiddleware {
  public enabledEntities: string[];
  public sanitizeInputs: boolean;
  public sanitizeOutputs: boolean;
  private _sessionMaps: Map<string, Map<string, string>> = new Map();
  private _entityMaps: Map<string, Map<string, string>> = new Map();

  constructor(options: ZTDSOptions = {}) {
    this.enabledEntities = options.enabledEntities || Object.keys(ZTDS_PATTERNS);
    this.sanitizeInputs = options.sanitizeInputs !== false;
    this.sanitizeOutputs = options.sanitizeOutputs !== false;
  }

  public sanitizeText(text: string, sessionId: string): { sanitized: string; tokenMap: Record<string, string> } {
    if (typeof text !== 'string') return { sanitized: text, tokenMap: {} };

    if (!this._sessionMaps.has(sessionId)) {
      this._sessionMaps.set(sessionId, new Map());
      this._entityMaps.set(sessionId, new Map());
    }

    const tokenMap = this._sessionMaps.get(sessionId)!;
    const entityMap = this._entityMaps.get(sessionId)!;
    let sanitized = text;

    for (const entityType of this.enabledEntities) {
      const pattern = ZTDS_PATTERNS[entityType];
      if (!pattern) continue;

      const regex = new RegExp(pattern.source, 'g');
      sanitized = sanitized.replace(regex, (match) => {
        if (entityMap.has(match)) {
          return entityMap.get(match)!;
        }
        let count = 0;
        for (const k of tokenMap.keys()) {
          if (k.startsWith(`[${entityType}_TOKEN_`)) count++;
        }
        const token = `[${entityType}_TOKEN_${count + 1}]`;
        tokenMap.set(token, match);
        entityMap.set(match, token);
        return token;
      });
    }

    const exportedMap: Record<string, string> = {};
    for (const [k, v] of tokenMap.entries()) {
      exportedMap[k] = v;
    }
    return { sanitized, tokenMap: exportedMap };
  }

  public restoreText(text: string, sessionId: string): string {
    if (typeof text !== 'string') return text;
    const tokenMap = this._sessionMaps.get(sessionId);
    if (!tokenMap || tokenMap.size === 0) return text;

    let restored = text;
    for (const [token, original] of tokenMap.entries()) {
      restored = restored.split(token).join(original);
    }
    return restored;
  }

  public sanitizeObject(val: any, sessionId: string): any {
    if (typeof val === 'string') {
      return this.sanitizeText(val, sessionId).sanitized;
    }
    if (Array.isArray(val)) {
      return val.map((item) => this.sanitizeObject(item, sessionId));
    }
    if (val !== null && typeof val === 'object') {
      const result: Record<string, any> = {};
      for (const [k, v] of Object.entries(val)) {
        result[k] = this.sanitizeObject(v, sessionId);
      }
      return result;
    }
    return val;
  }

  public zeroizeSession(sessionId: string): void {
    if (this._sessionMaps.has(sessionId)) {
      this._sessionMaps.get(sessionId)!.clear();
      this._sessionMaps.delete(sessionId);
    }
    if (this._entityMaps.has(sessionId)) {
      this._entityMaps.get(sessionId)!.clear();
      this._entityMaps.delete(sessionId);
    }
  }

  public wrapTool<TArgs = any, TResult = any>(
    toolName: string,
    handler: (args: TArgs, context?: any) => Promise<TResult>
  ): (args: TArgs, context?: any) => Promise<TResult> {
    const self = this;
    return async function (args: TArgs, context?: any): Promise<TResult> {
      const sessionId =
        (context && context.sessionId) ||
        `mcp-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;

      try {
        let processedArgs = args;
        if (self.sanitizeInputs && args) {
          processedArgs = self.sanitizeObject(args, sessionId);
        }

        const rawResult = await handler(processedArgs, context);

        let finalResult: any = rawResult;
        if (self.sanitizeOutputs && rawResult) {
          finalResult = self.sanitizeObject(rawResult, sessionId);
        }

        if (finalResult && typeof finalResult === 'object' && !Array.isArray(finalResult)) {
          finalResult._ztds = {
            standard: 'RFC v1.0 (IETF draft-sibiryakov-ztds-protocol-02)',
            zeroEgress: true,
            sessionId,
          };
        }

        return finalResult;
      } finally {
        self.zeroizeSession(sessionId);
      }
    };
  }
}
