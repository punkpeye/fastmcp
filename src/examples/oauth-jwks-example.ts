/**
 * JWKS (JSON Web Key Set) Verification Example
 *
 * This example demonstrates how to use the JWKSVerifier to verify tokens
 * using public keys from a JWKS endpoint.
 *
 * IMPORTANT: This requires the 'jose' package to be installed:
 * ```bash
 * npm install jose
 * ```
 */

import { FastMCP } from "../FastMCP.js";
import { JWKSVerifier, OAuthProxy } from "../auth/index.js";

/**
 * Example 1: Basic JWKS Verification
 * Verify tokens from Google's JWKS endpoint
 */
async function example1_basicJWKS() {
  const verifier = new JWKSVerifier({
    jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
    audience: "your-google-client-id.apps.googleusercontent.com",
    issuer: "https://accounts.google.com",
  });

  // Example token (you would get this from a real OAuth flow)
  const token = "eyJhbGciOiJSUzI1NiIs...";

  try {
    const result = await verifier.verify(token);

    if (result.valid) {
      console.log("Token is valid!");
      console.log("User:", result.claims?.client_id);
      console.log("Email:", result.claims?.email);
      console.log("All claims:", result.claims);
    } else {
      console.error("Token is invalid:", result.error);
    }
  } catch (error: any) {
    console.error("Verification failed:", error.message);
  }
}

/**
 * Example 2: JWKS with OAuth Proxy
 * Use JWKS verifier with OAuth Proxy for upstream token validation
 */
async function example2_withOAuthProxy() {
  // Create JWKS verifier for upstream provider
  const jwksVerifier = new JWKSVerifier({
    jwksUri: "https://login.microsoftonline.com/common/discovery/v2.0/keys",
    audience: "your-azure-client-id",
    issuer: "https://login.microsoftonline.com/{tenant}/v2.0",
  });

  // Create OAuth proxy with JWKS verification
  const authProxy = new OAuthProxy({
    baseUrl: "https://your-server.com",
    upstreamAuthorizationEndpoint:
      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    upstreamTokenEndpoint:
      "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    upstreamClientId: process.env.AZURE_CLIENT_ID!,
    upstreamClientSecret: process.env.AZURE_CLIENT_SECRET!,

    // Optional: Use JWKS verifier for additional upstream token validation
    tokenVerifier: jwksVerifier,
  });

  const server = new FastMCP({
    name: "Azure OAuth with JWKS",
    oauth: {
      enabled: true,
      authorizationServer: authProxy.getAuthorizationServerMetadata(),
      proxy: authProxy,
    },
  });

  await server.start({
    transportType: "httpStream",
    httpStream: { port: 3000 },
  });

  console.log("Server started with JWKS verification enabled");
}

/**
 * Example 3: Multi-Provider JWKS Verification
 * Support multiple identity providers
 */
async function example3_multiProvider() {
  // Create verifiers for different providers
  const googleVerifier = new JWKSVerifier({
    jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
    issuer: "https://accounts.google.com",
  });

  const auth0Verifier = new JWKSVerifier({
    jwksUri: "https://your-tenant.auth0.com/.well-known/jwks.json",
    issuer: "https://your-tenant.auth0.com/",
  });

  const oktaVerifier = new JWKSVerifier({
    jwksUri: "https://your-domain.okta.com/oauth2/v1/keys",
    issuer: "https://your-domain.okta.com",
  });

  // Verify token with appropriate provider
  async function verifyToken(token: string, provider: string) {
    let verifier: JWKSVerifier;

    switch (provider) {
      case "google":
        verifier = googleVerifier;
        break;
      case "auth0":
        verifier = auth0Verifier;
        break;
      case "okta":
        verifier = oktaVerifier;
        break;
      default:
        throw new Error(`Unknown provider: ${provider}`);
    }

    return await verifier.verify(token);
  }

  // Example usage
  const result = await verifyToken("eyJhbGc...", "google");
  console.log("Verification result:", result);
}

/**
 * Example 4: FastMCP Tool with JWKS Verification
 * Protect tools using JWKS-verified tokens
 */
async function example4_protectedTools() {
  const jwksVerifier = new JWKSVerifier({
    jwksUri: "https://your-identity-provider.com/.well-known/jwks.json",
    audience: "your-api-audience",
    issuer: "https://your-identity-provider.com",
  });

  const server = new FastMCP({
    name: "Protected API",
  });

  // Add a protected tool that verifies tokens using JWKS
  server.addTool({
    name: "get-user-data",
    description: "Get authenticated user data (JWKS-verified)",
    canAccess: async ({ session }) => {
      const authHeader = session?.headers?.["authorization"];
      if (!authHeader) {
        return false;
      }

      const token = authHeader.replace("Bearer ", "");

      // Verify token using JWKS
      const result = await jwksVerifier.verify(token);
      return result.valid;
    },
    execute: async (args, { session }) => {
      const token = session?.headers?.["authorization"]?.replace("Bearer ", "");

      if (!token) {
        throw new Error("No authorization token provided");
      }

      // Verify and extract claims
      const result = await jwksVerifier.verify(token!);

      if (!result.valid) {
        throw new Error(`Invalid token: ${result.error}`);
      }

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                user: result.claims?.sub || result.claims?.client_id,
                email: result.claims?.email,
                claims: result.claims,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  });

  await server.start({
    transportType: "httpStream",
    httpStream: { port: 3000 },
  });

  console.log("Server started with JWKS-protected tools");
}

/**
 * Example 5: Key Rotation Handling
 * Refresh JWKS keys when needed
 */
async function example5_keyRotation() {
  const verifier = new JWKSVerifier({
    jwksUri: "https://provider.com/.well-known/jwks.json",
    cacheDuration: 3600000, // Cache keys for 1 hour
    cooldownDuration: 30000, // Minimum 30s between refetches
  });

  // Normal verification
  let result = await verifier.verify("token1");

  // If you suspect keys have rotated, force a refresh
  if (!result.valid && result.error?.includes("unable to find key")) {
    console.log("Key not found, refreshing JWKS...");
    await verifier.refreshKeys();

    // Retry verification
    result = await verifier.verify("token1");
  }

  console.log("Verification result:", result);
}

// Run examples
if (import.meta.url === `file://${process.argv[1]}`) {
  console.log("JWKS Verification Examples");
  console.log("========================\n");

  console.log(
    "Note: These examples require 'jose' to be installed:\n  npm install jose\n",
  );

  // Uncomment the example you want to run:
  // example1_basicJWKS();
  // example2_withOAuthProxy();
  // example3_multiProvider();
  // example4_protectedTools();
  // example5_keyRotation();
}

export {
  example1_basicJWKS,
  example2_withOAuthProxy,
  example3_multiProvider,
  example4_protectedTools,
  example5_keyRotation,
};
