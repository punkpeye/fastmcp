/**
 * Example: Pay-per-call USDC billing with @lemon-cake/mcp-sdk
 *
 * Demonstrates how to add pay-per-call USDC billing to any FastMCP tool
 * using @lemon-cake/mcp-sdk — "Stripe for MCP servers".
 *
 * Features shown:
 * - Pay Token extraction from Authorization header via `authenticate`
 * - `withCharge()` adapter bridging FastMCP's execute API and LemonCake's billing
 * - Demo Mode (no LEMONCAKE_SELLER_KEY = logs charges but moves no real USDC)
 * - Earnings retrieval
 *
 * Prerequisites:
 *   npm install @lemon-cake/mcp-sdk
 *
 * Environment variables:
 *   LEMONCAKE_SELLER_KEY  — from lemoncake.xyz/dashboard (Seller → Account)
 *                           Omit to run in Demo Mode (no real charges)
 *
 * @see https://www.npmjs.com/package/@lemon-cake/mcp-sdk
 * @see https://lemoncake.xyz/sdk
 */

import { z } from "zod";
import { FastMCP, type Context, UserError } from "../FastMCP.js";

// ─── Install: npm install @lemon-cake/mcp-sdk ────────────────────────────────
// import { createLemonCakeSDK } from "@lemon-cake/mcp-sdk";
// import type { LemonCakeSDK, ChargeOptions } from "@lemon-cake/mcp-sdk";

// Stub types for this example (remove when importing the real SDK)
type ChargeOptions = { price: number; toolName?: string; freeCalls?: number };
type MCPResult = { content: { type: string; text: string }[]; isError?: boolean };
type LemonCakeSDK = {
  charge: (opts: ChargeOptions) => (fn: (args: Record<string, unknown>, extra?: { _meta?: Record<string, unknown> }) => Promise<MCPResult>) => (args: Record<string, unknown>, extra?: { _meta?: Record<string, unknown> }) => Promise<MCPResult>;
  getEarnings: () => Promise<unknown>;
};
function createLemonCakeSDK(cfg: { sellerKey?: string }): LemonCakeSDK {
  const demo = !cfg.sellerKey;
  if (demo) console.log("[LemonCake] Demo Mode — charges logged, no real USDC moved");
  return {
    charge: (opts) => (fn) => async (args, extra) => {
      const payToken = (extra?._meta as { payToken?: string })?.payToken ?? "demo";
      if (demo) console.log(`[LemonCake Demo] would charge $${opts.price} USDC (payToken=${payToken})`);
      return fn(args, extra);
    },
    getEarnings: async () => ({ totalUsdc: "0.00", pending: "0.00", confirmed: "0.00" }),
  };
}
// ─────────────────────────────────────────────────────────────────────────────

// ─── Session type: carries Pay Token extracted from Authorization header ──────
type BillingSession = {
  payToken: string | undefined;
};

// ─── LemonCake SDK init ───────────────────────────────────────────────────────
const lc = createLemonCakeSDK({
  sellerKey: process.env.LEMONCAKE_SELLER_KEY, // from lemoncake.xyz/dashboard
});

// ─── Adapter: bridge LemonCake charge() and FastMCP execute ──────────────────
/**
 * Wraps a FastMCP `execute` function with LemonCake pay-per-call billing.
 *
 * The Pay Token is pulled from `context.session.payToken` (set by `authenticate`
 * below). In Demo Mode (no LEMONCAKE_SELLER_KEY), charges are logged but no
 * real USDC moves.
 *
 * @example
 * execute: withCharge({ price: 0.05 }, async (args, context) => {
 *   return `result for ${args.query}`;
 * }),
 */
function withCharge<TArgs, TSession extends BillingSession>(
  options: ChargeOptions,
  handler: (args: TArgs, context: Context<TSession>) => Promise<string>,
) {
  return async (args: TArgs, context: Context<TSession>): Promise<string> => {
    // Inject Pay Token into the _meta object that lc.charge() reads
    const extra = { _meta: { payToken: context.session?.payToken } };

    const chargedHandler = lc.charge(options)(async (innerArgs) => {
      const text = await handler(innerArgs as TArgs, context);
      return { content: [{ type: "text", text }] };
    });

    const result = await chargedHandler(
      args as Record<string, unknown>,
      extra,
    );

    if (result.isError) {
      const msg =
        result.content.find((c) => c.type === "text")?.text ??
        "Payment failed";
      throw new UserError(msg); // surfaces as MCP error to the caller
    }

    return result.content.find((c) => c.type === "text")?.text ?? "";
  };
}

// ─── Server ───────────────────────────────────────────────────────────────────
const server = new FastMCP<BillingSession>({
  name: "Monetized MCP Server",
  version: "1.0.0",

  /**
   * Extract the Pay Token from the Authorization header.
   *
   * LemonCake-aware MCP clients (e.g. agent-payment-mcp) attach a JWT:
   *   Authorization: Bearer <lemoncake-pay-token>
   *
   * The token is then available as `context.session.payToken` in every tool.
   */
  authenticate: async (request) => {
    const auth = (request.headers as Record<string, string>)?.authorization ?? "";
    const payToken = auth.startsWith("Bearer ") ? auth.slice(7) : undefined;
    return { payToken };
  },
});

// ─── Monetized tools ──────────────────────────────────────────────────────────

/**
 * Tool 1: simple per-call price.
 * Charged $0.05 USDC per call. First 2 calls per session are free.
 */
server.addTool({
  name: "search_patents",
  description: "Search the patent database — $0.05 per search (first 2 free)",
  parameters: z.object({
    query: z.string().describe("Patent search query"),
  }),
  execute: withCharge<{ query: string }, BillingSession>(
    { price: 0.05, freeCalls: 2 },
    async (args) => {
      // Your actual tool logic here
      return `Found 12 patents matching "${args.query}"`;
    },
  ),
});

/**
 * Tool 2: higher price for a heavier operation.
 */
server.addTool({
  name: "analyze_contract",
  description: "AI contract risk analysis — $0.20 per document",
  parameters: z.object({
    text: z.string().describe("Contract text to analyze"),
  }),
  execute: withCharge<{ text: string }, BillingSession>(
    { price: 0.20 },
    async (args) => {
      // Your actual analysis logic here
      return `Contract analysis complete. ${args.text.length} characters reviewed. Risk: Low.`;
    },
  ),
});

/**
 * Tool 3: free tool — no billing wrapper needed.
 */
server.addTool({
  name: "ping",
  description: "Health check — always free",
  parameters: z.object({}),
  execute: async () => "pong",
});

/**
 * Tool 4: earnings dashboard for the seller.
 */
server.addTool({
  name: "get_earnings",
  description: "Retrieve your LemonCake earnings summary (seller only)",
  parameters: z.object({}),
  execute: async () => {
    const earnings = await lc.getEarnings();
    return JSON.stringify(earnings, null, 2);
  },
});

// ─── Start ────────────────────────────────────────────────────────────────────
server.start({ transportType: "stdio" });

console.error(
  "[LemonCake] Server started. " +
    (process.env.LEMONCAKE_SELLER_KEY
      ? "Live mode — real USDC charges enabled."
      : "Demo Mode — set LEMONCAKE_SELLER_KEY to enable real charges."),
);
