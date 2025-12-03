// Path: zn-vault-sdk-node/src/health/client.ts

import type { HttpClient } from '../http/client.js';

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  uptime: number;
  timestamp: string;
  checks?: {
    database?: { status: string; latencyMs?: number };
    encryption?: { status: string };
    kms?: { status: string };
  };
}

export interface ReadinessStatus {
  ready: boolean;
  checks: {
    database: boolean;
    encryption: boolean;
  };
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
