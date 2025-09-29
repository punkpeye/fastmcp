/**
 * Monkey-patches HTTP ServerResponse to fix authentication status codes.
 * 
 * When authentication is enabled in FastMCP, the MCP SDK incorrectly returns
 * 400 Bad Request for missing session IDs. This should be 401 Unauthorized.
 * 
 * This module patches the ServerResponse prototype to intercept and fix these
 * responses before they're sent to the client.
 */

import { IncomingMessage, ServerResponse } from "http";

let isPatched = false;
const authEnabledPorts = new Set<number>();

/**
 * Enables response patching for authentication errors on a specific port
 */
export function enableAuthResponsePatch(port: number): void {
  authEnabledPorts.add(port);
  if (!isPatched) {
    patchServerResponse();
  }
}

/**
 * Disables response patching for a specific port
 */
export function disableAuthResponsePatch(port: number): void {
  authEnabledPorts.delete(port);
}

/**
 * Patches ServerResponse to fix authentication status codes
 */
function patchServerResponse(): void {
  if (isPatched) return;
  
  const originalWriteHead = ServerResponse.prototype.writeHead;
  const originalEnd = ServerResponse.prototype.end;
  
  // Track response state per response object
  const responseStates = new WeakMap<ServerResponse, {
    statusCode?: number;
    headers?: any;
    intercepting?: boolean;
  }>();
  
  ServerResponse.prototype.writeHead = function(
    this: ServerResponse,
    statusCode: number,
    ...args: any[]
  ): ServerResponse {
    // Get the port from the socket
    const port = (this.socket as any)?.localPort;
    const shouldPatch = port && authEnabledPorts.has(port);
    
    if (!shouldPatch) {
      return originalWriteHead.apply(this, [statusCode, ...args]);
    }
    
    // Initialize state for this response
    if (!responseStates.has(this)) {
      responseStates.set(this, {});
    }
    const state = responseStates.get(this)!;
    
    state.statusCode = statusCode;
    
    // Parse headers from various argument formats
    if (typeof args[0] === "string") {
      state.headers = args[1] || {};
    } else if (typeof args[0] === "object") {
      state.headers = args[0] || {};
    }
    
    // If this is a 400, we might need to intercept
    if (statusCode === 400) {
      state.intercepting = true;
      // Don't call original writeHead yet
      return this;
    }
    
    // For non-400, proceed normally
    return originalWriteHead.apply(this, [statusCode, ...args]);
  };
  
  ServerResponse.prototype.end = function(
    this: ServerResponse,
    chunk?: any,
    ...args: any[]
  ): ServerResponse {
    // Get the port from the socket
    const port = (this.socket as any)?.localPort;
    const shouldPatch = port && authEnabledPorts.has(port);
    
    if (!shouldPatch) {
      return originalEnd.apply(this, [chunk, ...args]);
    }
    
    const state = responseStates.get(this);
    
    // If we're not intercepting this response, proceed normally
    if (!state?.intercepting) {
      return originalEnd.apply(this, [chunk, ...args]);
    }
    
    // We're intercepting a 400 response
    let body = "";
    if (chunk) {
      if (typeof chunk === "string") {
        body = chunk;
      } else if (Buffer.isBuffer(chunk)) {
        body = chunk.toString();
      } else {
        body = JSON.stringify(chunk);
      }
    }
    
    // Check if this is an auth-related 400 that should be 401
    try {
      const json = JSON.parse(body);
      
      if (
        json.error?.message?.match(/session.?id|no valid session/i) ||
        json.error?.message?.includes("Mcp-Session-Id") ||
        json.error?.message?.includes("Bad Request: Mcp-Session-Id")
      ) {
        // Fix the status code and message
        const fixedStatus = 401;
        const fixedHeaders = {
          ...state.headers,
          "WWW-Authenticate": 'Bearer realm="api"',
        };
        
        // Update error message
        if (json.error) {
          json.error.message = json.error.message.replace(
            /^Bad Request:/,
            "Unauthorized:"
          );
        }
        
        const fixedBody = JSON.stringify(json);
        
        // Now write the fixed response
        originalWriteHead.apply(this, [fixedStatus, fixedHeaders]);
        return originalEnd.apply(this, [fixedBody, ...args]);
      }
    } catch (e) {
      // Not JSON or not an auth error, proceed with original 400
    }
    
    // Write the original 400 response
    originalWriteHead.apply(this, [state.statusCode, state.headers]);
    return originalEnd.apply(this, [chunk, ...args]);
  };
  
  isPatched = true;
}

/**
 * Restores the original ServerResponse methods
 */
export function unpatchServerResponse(): void {
  // Note: In practice, we don't unpatch because it could affect other code
  // This is here for completeness but shouldn't be called in production
  authEnabledPorts.clear();
}