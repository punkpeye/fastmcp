/**
 * Consent Management
 * Handles user consent flow for OAuth authorization
 */

import { createHmac } from "crypto";

import type { ConsentData, OAuthTransaction } from "../types.js";

import { equalsConstantTime } from "./constantTime.js";

/**
 * Manages consent screens and cookie signing
 */
export class ConsentManager {
  private signingKey: string;

  constructor(signingKey: string) {
    this.signingKey = signingKey || this.generateDefaultKey();
  }

  /**
   * Create HTTP response with consent screen
   *
   * `cookie` is a `Set-Cookie` value that ties the request to the browser the
   * screen is shown to. The screen may not be framed: a page that embeds it
   * could have the user approve without seeing what they are approving.
   */
  createConsentResponse(
    transaction: OAuthTransaction,
    provider: string,
    options: { clientName?: string; cookie?: string } = {},
  ): Response {
    const consentData: ConsentData = {
      clientName: options.clientName || "MCP Client",
      provider,
      redirectUri: transaction.clientCallbackUrl,
      scope: transaction.scope,
      timestamp: Date.now(),
      transactionId: transaction.id,
    };

    const html = this.generateConsentScreen(consentData);
    const headers = new Headers({
      "Cache-Control": "no-store",
      "Content-Security-Policy": "frame-ancestors 'none'",
      "Content-Type": "text/html; charset=utf-8",
      "X-Frame-Options": "DENY",
    });

    if (options.cookie) {
      headers.append("Set-Cookie", options.cookie);
    }

    return new Response(html, { headers, status: 200 });
  }

  /**
   * Generate HTML for consent screen
   */
  generateConsentScreen(data: ConsentData): string {
    const { clientName, provider, redirectUri, scope, transactionId } = data;
    // A client names itself, so the name alone says little. Where the user is
    // sent afterwards is what the client cannot make up.
    const destination = redirectUri && this.describeDestination(redirectUri);

    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorization Request</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }

        .consent-container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 480px;
            width: 100%;
            padding: 40px;
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
        }

        .header h1 {
            color: #1a202c;
            font-size: 24px;
            margin-bottom: 8px;
        }

        .header p {
            color: #718096;
            font-size: 14px;
        }

        .app-info {
            background: #f7fafc;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }

        .app-info h2 {
            color: #2d3748;
            font-size: 18px;
            margin-bottom: 12px;
        }

        .app-name {
            color: #667eea;
            font-weight: 600;
        }

        .destination {
            color: #4a5568;
            font-size: 14px;
            overflow-wrap: anywhere;
        }

        .permissions {
            margin-top: 16px;
        }

        .permissions h3 {
            color: #4a5568;
            font-size: 14px;
            margin-bottom: 8px;
            font-weight: 600;
        }

        .permissions ul {
            list-style: none;
        }

        .permissions li {
            color: #718096;
            font-size: 14px;
            padding: 6px 0;
            padding-left: 24px;
            position: relative;
        }

        .permissions li:before {
            content: "✓";
            position: absolute;
            left: 0;
            color: #48bb78;
            font-weight: bold;
        }

        .warning {
            background: #fffaf0;
            border-left: 4px solid #ed8936;
            padding: 12px 16px;
            margin-bottom: 24px;
            border-radius: 4px;
        }

        .warning p {
            color: #744210;
            font-size: 13px;
            line-height: 1.5;
        }

        .actions {
            display: flex;
            gap: 12px;
        }

        button {
            flex: 1;
            padding: 14px 24px;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }

        .approve {
            background: #667eea;
            color: white;
        }

        .approve:hover {
            background: #5a67d8;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }

        .deny {
            background: #e2e8f0;
            color: #4a5568;
        }

        .deny:hover {
            background: #cbd5e0;
        }

        .footer {
            margin-top: 24px;
            text-align: center;
            color: #a0aec0;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="consent-container">
        <div class="header">
            <h1>🔐 Authorization Request</h1>
            <p>via ${this.escapeHtml(provider)}</p>
        </div>

        <div class="app-info">
            <h2>
                <span class="app-name">${this.escapeHtml((clientName || "An application").slice(0, 100))}</span>
                requests access
            </h2>
${
  destination
    ? `
            <p class="destination">
                If you approve, you will be sent to
                <strong>${this.escapeHtml(destination)}</strong>
            </p>
`
    : ""
}
            <div class="permissions">
                <h3>This will allow the app to:</h3>
                <ul>
                    ${scope.map((s) => `<li>${this.escapeHtml(this.formatScope(s))}</li>`).join("")}
                </ul>
            </div>
        </div>

        <div class="warning">
            <p>
                <strong>⚠️ Important:</strong> Only approve if you trust this application.
                By approving, you authorize it to access your account information.
            </p>
        </div>

        <form method="POST" action="consent">
            <input type="hidden" name="transaction_id" value="${this.escapeHtml(transactionId)}">
            <div class="actions">
                <button type="submit" name="action" value="deny" class="deny">
                    Deny
                </button>
                <button type="submit" name="action" value="approve" class="approve">
                    Approve
                </button>
            </div>
        </form>

        <div class="footer">
            <p>This consent is required to prevent unauthorized access.</p>
        </div>
    </div>
</body>
</html>
    `.trim();
  }

  /**
   * Sign consent data for cookie
   */
  signConsentCookie(data: ConsentData): string {
    const payload = JSON.stringify(data);
    const signature = this.sign(payload);

    return `${Buffer.from(payload).toString("base64")}.${signature}`;
  }

  /**
   * Validate and parse consent cookie
   */
  validateConsentCookie(cookie: string): ConsentData | null {
    try {
      const [payloadB64, signature] = cookie.split(".");

      if (!payloadB64 || !signature) {
        return null;
      }

      const payload = Buffer.from(payloadB64, "base64").toString("utf8");
      const expectedSignature = this.sign(payload);

      // Constant-time HMAC comparison (CWE-208): a plain `!==` leaks, via
      // timing, how many leading bytes of the cookie signature are correct.
      // Both operands are fixed-length hex digests, so the length check inside
      // the helper reveals nothing.
      if (!equalsConstantTime(signature, expectedSignature)) {
        return null;
      }

      const data = JSON.parse(payload) as ConsentData;

      // Check if consent is still valid (5 minutes)
      const age = Date.now() - data.timestamp;
      if (age > 5 * 60 * 1000) {
        return null;
      }

      return data;
    } catch {
      return null;
    }
  }

  /**
   * Where a redirect URI leads, as the browser will read it rather than as it
   * was typed: the parsed host, so that a look-alike character, a tab or a
   * backslash shows for what it does. A long host keeps its end, which is the
   * part that says whose it is.
   */
  private describeDestination(redirectUri: string): string | undefined {
    let url: URL;

    try {
      url = new URL(redirectUri);
    } catch {
      return undefined;
    }

    const host = url.host.length > 80 ? `…${url.host.slice(-80)}` : url.host;
    const path =
      url.pathname.length > 80 ? `${url.pathname.slice(0, 80)}…` : url.pathname;

    return host ? `${url.protocol}//${host}${path}` : `${url.protocol}${path}`;
  }

  /**
   * Escape HTML to prevent XSS
   */
  private escapeHtml(text: string): string {
    const map: Record<string, string> = {
      "'": "&#x27;",
      '"': "&quot;",
      "/": "&#x2F;",
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
    };

    return text.replace(/[&<>"'/]/g, (char) => map[char] || char);
  }

  /**
   * Format scope for display
   */
  private formatScope(scope: string): string {
    // Convert scope names to readable format
    const scopeMap: Record<string, string> = {
      email: "Access your email address",
      openid: "Verify your identity",
      profile: "View your basic profile information",
      "read:user": "Read your user information",
      "write:user": "Modify your user information",
    };

    return scopeMap[scope] || scope.replace(/_/g, " ").replace(/:/g, " - ");
  }

  /**
   * Generate default signing key if none provided
   */
  private generateDefaultKey(): string {
    return `fastmcp-consent-${Date.now()}-${Math.random()}`;
  }

  /**
   * Sign a payload using HMAC-SHA256
   */
  private sign(payload: string): string {
    return createHmac("sha256", this.signingKey).update(payload).digest("hex");
  }
}
