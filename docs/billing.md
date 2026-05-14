# Pay-per-call Billing with @lemon-cake/mcp-sdk

Add USDC micropayment billing to any FastMCP tool using [`@lemon-cake/mcp-sdk`](https://www.npmjs.com/package/@lemon-cake/mcp-sdk) — "Stripe for MCP servers".

## Installation

```bash
npm install @lemon-cake/mcp-sdk
```

Requires `@modelcontextprotocol/sdk` >= 1.10.0 (already a FastMCP peer dep).

## Quick Start

```typescript
import { FastMCP, UserError } from "fastmcp";
import { createLemonCakeSDK } from "@lemon-cake/mcp-sdk";
import { z } from "zod";

type BillingSession = { payToken: string | undefined };

// Initialize SDK — omit sellerKey to run in Demo Mode (no real charges)
const lc = createLemonCakeSDK({
  sellerKey: process.env.LEMONCAKE_SELLER_KEY,
});

const server = new FastMCP<BillingSession>({
  name: "My Server",
  version: "1.0.0",
  // Extract Pay Token from Authorization header
  authenticate: async (request) => {
    const auth = request.headers?.authorization ?? "";
    const payToken = auth.startsWith("Bearer ") ? auth.slice(7) : undefined;
    return { payToken };
  },
});

// Adapter: bridges FastMCP execute and LemonCake charge()
function withCharge(
  options: { price: number; freeCalls?: number },
  handler: (args: any, context: any) => Promise<string>,
) {
  return async (args: any, context: any): Promise<string> => {
    const extra = { _meta: { payToken: context.session?.payToken } };
    const charged = lc.charge(options)(async (a) => ({
      content: [{ type: "text" as const, text: await handler(a, context) }],
    }));
    const result = await charged(args, extra);
    if (result.isError) {
      throw new UserError(result.content.find((c) => c.type === "text")?.text ?? "Payment failed");
    }
    return result.content.find((c) => c.type === "text")?.text ?? "";
  };
}

// Monetized tool — $0.05 per call, first 2 calls free
server.addTool({
  name: "search_patents",
  description: "Patent search — $0.05 per call (first 2 free)",
  parameters: z.object({ query: z.string() }),
  execute: withCharge({ price: 0.05, freeCalls: 2 }, async (args) => {
    return `Results for: ${args.query}`;
  }),
});

server.start({ transportType: "stdio" });
```

## How It Works

```
Agent operator                  Your FastMCP server          LemonCake API
─────────────────               ─────────────────────        ─────────────
Issue Pay Token  ────────────►  authenticate()               
                                  └─ payToken in session      
Call tool ──────────────────►   execute(args, context)        
  Authorization: Bearer <jwt>     withCharge()               preflight ──►
                                    handler runs              confirm  ──►
Result ◄────────────────────    return result                  USDC settled
```

1. The **agent operator** issues a Pay Token on [lemoncake.xyz](https://lemoncake.xyz) with a USDC budget
2. The **MCP client** attaches it as `Authorization: Bearer <token>`
3. `authenticate()` extracts it into `context.session.payToken`
4. `withCharge()` calls LemonCake's preflight API before running your handler
5. On success, the charge is confirmed and USDC settles to your wallet

## Demo Mode

If `LEMONCAKE_SELLER_KEY` is not set, the SDK runs in **Demo Mode**:
- All tool calls pass through normally
- Charges are logged but no real USDC moves
- Useful for local development and CI

```bash
# Demo Mode (default — no env var needed)
npx fastmcp dev lemoncake-billing.ts

# Live mode
LEMONCAKE_SELLER_KEY=<your-key> npx fastmcp dev lemoncake-billing.ts
```

## Getting Your Seller Key

1. Sign in at [lemoncake.xyz](https://lemoncake.xyz)
2. Switch to **Seller** role
3. Go to **Account** → copy the **SDK Seller Key**
4. Set `LEMONCAKE_SELLER_KEY` in your environment

## Earnings

```typescript
const earnings = await lc.getEarnings();
// { totalUsdc: "1.23", pending: "0.05", confirmed: "1.18", byTool: [...] }
```

## Full Example

See [`src/examples/lemoncake-billing.ts`](../src/examples/lemoncake-billing.ts) for a complete working example with multiple monetized tools, free tiers, and earnings reporting.
