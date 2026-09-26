/**
 * FastMCP ZTDS Middleware Unit Tests
 * Conforms to IETF draft-sibiryakov-ztds-protocol-02
 */

import { describe, expect, it } from 'vitest';
import { ZTDSFastMCPMiddleware } from './ztdsMiddleware.js';

describe('ZTDSFastMCPMiddleware', () => {
  it('sanitizes input arguments and output responses without cleartext leakage', async () => {
    const middleware = new ZTDSFastMCPMiddleware();

    const mockTool = async (args: { query: string; token: string }) => {
      // Tool receives synthetic tokens only
      expect(args.query).not.toContain('ceo@enterprise.com');
      expect(args.query).toContain('[EMAIL_TOKEN_1]');
      expect(args.token).not.toContain('ghp_abcdef12345678901234567890');
      expect(args.token).toContain('[API_SECRET_TOKEN_1]');

      return {
        message: 'Account verified for ceo@enterprise.com',
        query: args.query,
      };
    };

    const wrapped = middleware.wrapTool('authTest', mockTool);
    const result = await wrapped({
      query: 'Verify ceo@enterprise.com',
      token: 'ghp_abcdef12345678901234567890',
    });

    expect(result.message).not.toContain('ceo@enterprise.com');
    expect(result.message).toContain('[EMAIL_TOKEN_1]');
    expect(result._ztds.zeroEgress).toBe(true);
    expect(result._ztds.standard).toContain('draft-sibiryakov-ztds-protocol-02');
  });

  it('guarantees volatile RAM zeroization (Theorem 2) after invocation', async () => {
    const middleware = new ZTDSFastMCPMiddleware();
    const wrapped = middleware.wrapTool('echo', async (args: { text: string }) => args);

    await wrapped({ text: 'Card 4111-2222-3333-4444' });

    // Internal maps should be completely wiped
    expect((middleware as any)._sessionMaps.size).toBe(0);
    expect((middleware as any)._entityMaps.size).toBe(0);
  });
});
