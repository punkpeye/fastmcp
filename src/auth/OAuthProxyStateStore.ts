import { z } from "zod";

import type {
  ClientCode,
  OAuthTransaction,
  ProxyDCRClient,
  TokenStorage,
  UpstreamTokenSet,
} from "./types.js";

const STORAGE_KEY_PREFIX = {
  client: "client:",
  code: "code:",
  transaction: "transaction:",
} as const;

const storedDateSchema = z
  .union([z.date(), z.string()])
  .transform((value, context) => {
    const date = value instanceof Date ? value : new Date(value);

    if (Number.isNaN(date.getTime())) {
      context.addIssue({
        code: "custom",
        message: "Invalid stored date",
      });
      return z.NEVER;
    }

    return date;
  });

const dcrClientMetadataSchema = z.object({
  client_name: z.string().optional(),
  client_uri: z.string().optional(),
  contacts: z.array(z.string()).optional(),
  jwks: z.record(z.string(), z.unknown()).optional(),
  jwks_uri: z.string().optional(),
  logo_uri: z.string().optional(),
  policy_uri: z.string().optional(),
  scope: z.string().optional(),
  software_id: z.string().optional(),
  software_version: z.string().optional(),
  tos_uri: z.string().optional(),
});

const proxyDcrClientStorageSchema: z.ZodType<ProxyDCRClient> = z.object({
  callbackUrl: z.string(),
  clientId: z.string(),
  clientSecret: z.string().optional(),
  metadata: dcrClientMetadataSchema.optional(),
  redirectUris: z.array(z.string()),
  registeredAt: storedDateSchema,
});

const upstreamTokenSetStorageSchema: z.ZodType<UpstreamTokenSet> = z.object({
  accessToken: z.string(),
  expiresIn: z.number(),
  idToken: z.string().optional(),
  issuedAt: storedDateSchema,
  refreshExpiresIn: z.number().optional(),
  refreshToken: z.string().optional(),
  scope: z.array(z.string()),
  tokenType: z.string(),
});

const clientCodeStorageSchema: z.ZodType<ClientCode> = z.object({
  clientId: z.string(),
  code: z.string(),
  codeChallenge: z.string(),
  codeChallengeMethod: z.string(),
  createdAt: storedDateSchema,
  expiresAt: storedDateSchema,
  transactionId: z.string(),
  upstreamTokens: upstreamTokenSetStorageSchema,
  used: z.boolean().optional(),
});

const oauthTransactionStorageSchema: z.ZodType<OAuthTransaction> = z.object({
  clientCallbackUrl: z.string(),
  clientCodeChallenge: z.string(),
  clientCodeChallengeMethod: z.string(),
  clientId: z.string(),
  consentGiven: z.boolean().optional(),
  createdAt: storedDateSchema,
  expiresAt: storedDateSchema,
  id: z.string(),
  metadata: z.record(z.string(), z.unknown()).optional(),
  proxyCodeChallenge: z.string(),
  proxyCodeVerifier: z.string(),
  scope: z.array(z.string()),
  state: z.string(),
});

interface OAuthProxyStateStoreConfig {
  readonly registeredClients: Map<string, ProxyDCRClient>;
  readonly registeredClientsByClientId: Map<string, ProxyDCRClient>;
  readonly tokenStorage: TokenStorage;
}

/**
 * Backs OAuth proxy state with the configured TokenStorage so that several
 * proxy instances can serve one flow.
 *
 * Client registrations are immutable once written, so they are cached locally.
 * Transactions and authorization codes are *not* cached: they are single-use
 * and mutated by whichever instance handles the next leg of the flow, so a
 * local copy would go stale and let a consumed code or transaction be redeemed
 * a second time.
 */
export class OAuthProxyStateStore {
  private readonly registeredClients: Map<string, ProxyDCRClient>;
  private readonly registeredClientsByClientId: Map<string, ProxyDCRClient>;
  private readonly tokenStorage: TokenStorage;

  constructor(config: OAuthProxyStateStoreConfig) {
    this.registeredClients = config.registeredClients;
    this.registeredClientsByClientId = config.registeredClientsByClientId;
    this.tokenStorage = config.tokenStorage;
  }

  cacheRegisteredClient(client: ProxyDCRClient): void {
    this.registeredClientsByClientId.set(client.clientId, client);

    for (const uri of client.redirectUris) {
      this.registeredClients.set(uri, client);
    }
  }

  /**
   * Atomically consume an authorization code. At most one caller — across all
   * processes sharing the storage — can receive a given code, which is what
   * makes single use enforceable (RFC 6749 §4.1.2).
   */
  async consumeClientCode(code: string): Promise<ClientCode | null> {
    const stored = await this.takeFromStorage(
      `${STORAGE_KEY_PREFIX.code}${code}`,
    );
    const parsed = clientCodeStorageSchema.safeParse(stored);

    if (!parsed.success || this.isExpired(parsed.data.expiresAt)) {
      return null;
    }

    return parsed.data;
  }

  /**
   * Atomically consume a transaction, so a callback can only be redeemed once
   * no matter which instance it lands on.
   */
  async consumeTransaction(
    transactionId: string,
  ): Promise<null | OAuthTransaction> {
    const stored = await this.takeFromStorage(
      `${STORAGE_KEY_PREFIX.transaction}${transactionId}`,
    );
    const parsed = oauthTransactionStorageSchema.safeParse(stored);

    if (!parsed.success || this.isExpired(parsed.data.expiresAt)) {
      return null;
    }

    return parsed.data;
  }

  async deleteClientCode(code: string): Promise<void> {
    await this.tokenStorage.delete(`${STORAGE_KEY_PREFIX.code}${code}`);
  }

  async deleteTransaction(transactionId: string): Promise<void> {
    await this.tokenStorage.delete(
      `${STORAGE_KEY_PREFIX.transaction}${transactionId}`,
    );
  }

  async getRegisteredClientByClientId(
    clientId: string,
  ): Promise<null | ProxyDCRClient> {
    const cached = this.registeredClientsByClientId.get(clientId);
    if (cached) {
      return cached;
    }

    const stored = await this.tokenStorage.get(
      `${STORAGE_KEY_PREFIX.client}${clientId}`,
    );
    const parsed = proxyDcrClientStorageSchema.safeParse(stored);

    if (!parsed.success) {
      return null;
    }

    this.cacheRegisteredClient(parsed.data);
    return parsed.data;
  }

  /**
   * Read a transaction without consuming it. Used by the consent screen, which
   * has to hand the same transaction back to the upstream redirect.
   */
  async getTransaction(
    transactionId: string,
  ): Promise<null | OAuthTransaction> {
    const stored = await this.tokenStorage.get(
      `${STORAGE_KEY_PREFIX.transaction}${transactionId}`,
    );
    const parsed = oauthTransactionStorageSchema.safeParse(stored);

    if (!parsed.success) {
      return null;
    }

    if (this.isExpired(parsed.data.expiresAt)) {
      await this.deleteTransaction(transactionId);
      return null;
    }

    return parsed.data;
  }

  async isTransactionCallbackRegistered(
    transaction: OAuthTransaction,
  ): Promise<boolean> {
    const registeredClient = await this.getRegisteredClientByClientId(
      transaction.clientId,
    );

    return (
      registeredClient?.redirectUris.includes(transaction.clientCallbackUrl) ??
      false
    );
  }

  async saveClientCode(clientCode: ClientCode): Promise<void> {
    await this.tokenStorage.save(
      `${STORAGE_KEY_PREFIX.code}${clientCode.code}`,
      clientCode,
      this.getTtlSeconds(clientCode.expiresAt),
    );
  }

  async saveRegisteredClient(client: ProxyDCRClient): Promise<void> {
    await this.tokenStorage.save(
      `${STORAGE_KEY_PREFIX.client}${client.clientId}`,
      client,
    );
  }

  async saveTransaction(transaction: OAuthTransaction): Promise<void> {
    await this.tokenStorage.save(
      `${STORAGE_KEY_PREFIX.transaction}${transaction.id}`,
      transaction,
      this.getTtlSeconds(transaction.expiresAt),
    );
  }

  private getTtlSeconds(expiresAt: Date): number {
    const millisecondsUntilExpiry = expiresAt.getTime() - Date.now();
    return Math.max(Math.ceil(millisecondsUntilExpiry / 1000), 1);
  }

  private isExpired(expiresAt: Date): boolean {
    return expiresAt.getTime() < Date.now();
  }

  /**
   * Prefer the storage's atomic take. Falling back to get + delete leaves a
   * window in which two processes can both observe the same value, so
   * multi-process deployments should implement `TokenStorage.take`.
   */
  private async takeFromStorage(key: string): Promise<null | unknown> {
    if (this.tokenStorage.take) {
      return this.tokenStorage.take(key);
    }

    const stored = await this.tokenStorage.get(key);

    if (stored === null) {
      return null;
    }

    await this.tokenStorage.delete(key);

    return stored;
  }
}
