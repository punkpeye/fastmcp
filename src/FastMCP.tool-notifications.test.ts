import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it, vi } from "vitest";

import { FastMCP } from "./FastMCP.js";

describe("tool notifications after abort", () => {
  it.each(["cancel", "timeout", "close"])(
    "stops notifications and timers after %s",
    async (ending) => {
      const resume = Promise.withResolvers<void>();
      const running = Promise.withResolvers<void>();
      const stopped = Promise.withResolvers<void>();
      const notified = Promise.withResolvers<void>();
      const server = new FastMCP({
        name: "Test",
        streamKeepalive: { enabled: true, intervalMs: 1000 },
        version: "1.0.0",
      });
      server.addTool({
        execute: async (_args, context) => {
          context.signal.addEventListener("abort", () => stopped.resolve(), {
            once: true,
          });
          const notify = async () => {
            await context.reportProgress({ progress: 1, total: 2 });
            await context.streamContent({ text: "chunk", type: "text" });
            context.log.info("still working");
          };
          await notify();
          running.resolve();
          await resume.promise;
          await notify();
          notified.resolve();
          return "done";
        },
        name: "slow",
        timeoutMs: ending === "timeout" ? 50 : 10000,
      });
      const [clientTransport, serverTransport] =
        InMemoryTransport.createLinkedPair();
      const send = vi.spyOn(serverTransport, "send");
      const client = new Client({ name: "test-client", version: "1.0.0" });
      const [session] = await Promise.all([
        server.connect(serverTransport),
        client.connect(clientTransport),
      ]);

      if (ending !== "timeout") {
        vi.useFakeTimers({
          toFake: [
            "setTimeout",
            "clearTimeout",
            "setInterval",
            "clearInterval",
          ],
        });
      }
      try {
        const cancel = new AbortController();
        const call = client
          .callTool({ name: "slow" }, undefined, {
            onprogress: () => {},
            signal: cancel.signal,
            timeout: 500,
          })
          .catch(() => "cancelled");
        await running.promise;
        const notificationMethods = () =>
          send.mock.calls.flatMap(([message]) =>
            "method" in message ? [message.method] : [],
          );
        expect(notificationMethods()).toEqual([
          "notifications/progress",
          "notifications/tool/streamContent",
          "notifications/message",
        ]);

        if (ending === "cancel") {
          cancel.abort();
        } else if (ending === "close") {
          await session.close();
        }
        await stopped.promise;
        await call;
        if (ending === "close") {
          // Drain the SDK client's request timeout, which survives close().
          await vi.advanceTimersByTimeAsync(3000);
        }
        send.mockClear();
        if (ending !== "timeout") {
          expect.soft(vi.getTimerCount()).toBe(0);
        }

        resume.resolve();
        await notified.promise;
        expect(notificationMethods()).toEqual([]);
      } finally {
        resume.resolve();
        if (ending !== "timeout") {
          await vi.runOnlyPendingTimersAsync();
          vi.useRealTimers();
        }
        await client.close();
        await session.close();
      }
    },
  );
});
