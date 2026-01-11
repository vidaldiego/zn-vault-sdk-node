// Path: zn-vault-sdk-node/src/audit/client.ts

import type { HttpClient } from '../http/client.js';
import type {
  AuditEntry,
  AuditFilter,
  PaginatedResponse,
} from '../types/index.js';

export interface AuditVerifyResult {
  valid: boolean;
  totalEntries: number;
  verifiedEntries: number;
  firstBrokenEntry?: number;
  error?: string;
}

export class AuditClient {
  constructor(private http: HttpClient) {}

  async list(filter?: AuditFilter): Promise<PaginatedResponse<AuditEntry>> {
    const params = new URLSearchParams();
    if (filter?.tenantId) params.set('tenantId', filter.tenantId);
    if (filter?.userId) params.set('userId', filter.userId);
    if (filter?.action) params.set('action', filter.action);
    if (filter?.resourceType) params.set('resourceType', filter.resourceType);
    if (filter?.startDate) params.set('startDate', filter.startDate);
    if (filter?.endDate) params.set('endDate', filter.endDate);
    if (filter?.limit) params.set('limit', filter.limit.toString());
    if (filter?.offset) params.set('offset', filter.offset.toString());

    const query = params.toString();
    const path = query ? `/v1/audit?${query}` : '/v1/audit';
    return this.http.get<PaginatedResponse<AuditEntry>>(path);
  }

  async get(id: string): Promise<AuditEntry> {
    return this.http.get<AuditEntry>(`/v1/audit/${id}`);
  }

  async verify(): Promise<AuditVerifyResult> {
    return this.http.get<AuditVerifyResult>('/v1/audit/verify');
  }

  async exportLogs(filter?: AuditFilter): Promise<AuditEntry[]> {
    const params = new URLSearchParams();
    if (filter?.tenantId) params.set('tenantId', filter.tenantId);
    if (filter?.userId) params.set('userId', filter.userId);
    if (filter?.action) params.set('action', filter.action);
    if (filter?.resourceType) params.set('resourceType', filter.resourceType);
    if (filter?.startDate) params.set('startDate', filter.startDate);
    if (filter?.endDate) params.set('endDate', filter.endDate);

    const query = params.toString();
    const path = query ? `/v1/audit/export?${query}` : '/v1/audit/export';
    const response = await this.http.get<{ entries: AuditEntry[] }>(path);
    return response.entries;
  }
}
