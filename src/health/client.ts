// Path: zn-vault-sdk-node/src/health/client.ts

import type { HttpClient } from '../http/client.js';

/**
 * Individual health check result from the server.
 * Each named check (db, tls) emits { status, details? }.
 */
export interface HealthCheck {
  status: string;
  details?: Record<string, unknown>;
}

/**
 * Response from GET /v1/health.
 *
 * - `status`: overall system status
 * - `checks.db` / `checks.tls`: always present; `checks.kmip` only on KMIP-enabled nodes
 */
export interface HealthStatus {
  status: 'ok' | 'degraded' | 'error';
  version: string;
  uptime: number;
  timestamp: string;
  buildTime?: string;
  gitCommit?: string;
  environment?: string;
  totpRequired?: boolean;
  checks: {
    db: HealthCheck;
    tls: HealthCheck;
    kmip?: {
      enabled: boolean;
      listening: boolean;
      port: number;
      serverCertDaysToExpiry: number | null;
    };
  };
}

/**
 * Response from GET /v1/health/ready.
 *
 * Returns 200 when ready, 503 when not ready or degraded (stuck LMK rotation).
 */
export interface ReadinessStatus {
  status: 'ready' | 'not ready' | 'degraded';
  timestamp: string;
  reason?: string;
}

export class HealthClient {
  constructor(private http: HttpClient) {}

  async check(): Promise<HealthStatus> {
    return this.http.get<HealthStatus>('/v1/health');
  }

  async ready(): Promise<ReadinessStatus> {
    return this.http.get<ReadinessStatus>('/v1/health/ready');
  }

  async live(): Promise<{ status: 'ok' }> {
    return this.http.get<{ status: 'ok' }>('/v1/health/live');
  }
}
