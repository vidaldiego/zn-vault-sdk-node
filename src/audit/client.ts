// Path: zn-vault-sdk-node/src/audit/client.ts

import type { HttpClient } from '../http/client.js';
import type {
  AuditEntry,
  AuditFilter,
  AuditListResponse,
  AuditStats,
  AuditVerifyResult,
} from '../types/index.js';

export class AuditClient {
  constructor(private http: HttpClient) {}

  /**
   * List audit log entries with optional filtering and pagination.
   * Returns items, pagination metadata, and summary stats.
   *
   * Query params are sent as snake_case to match the server contract:
   * client_cn, action, resource, start_date, end_date, limit, offset.
   */
  async list(filter?: AuditFilter): Promise<AuditListResponse> {
    const params = new URLSearchParams();
    if (filter?.clientCn) params.set('client_cn', filter.clientCn);
    if (filter?.action) params.set('action', filter.action);
    if (filter?.resource) params.set('resource', filter.resource);
    if (filter?.startDate) params.set('start_date', filter.startDate);
    if (filter?.endDate) params.set('end_date', filter.endDate);
    if (filter?.limit !== undefined) params.set('limit', filter.limit.toString());
    if (filter?.offset !== undefined) params.set('offset', filter.offset.toString());

    const query = params.toString();
    const path = query ? `/v1/audit?${query}` : '/v1/audit';
    return this.http.get<AuditListResponse>(path);
  }

  /**
   * Verify the HMAC chain integrity of the audit log.
   * Returns validation status, any errors found, and a timestamp.
   */
  async verify(): Promise<AuditVerifyResult> {
    return this.http.get<AuditVerifyResult>('/v1/audit/verify');
  }

  /**
   * Export audit logs as a JSON array or CSV.
   * Returns the bare array of entries (JSON) or a CSV string.
   *
   * Note: the server returns a bare JSON array (not wrapped in an object).
   */
  async exportLogs(filter?: AuditFilter): Promise<AuditEntry[]> {
    const params = new URLSearchParams();
    if (filter?.format) params.set('format', filter.format);
    if (filter?.clientCn) params.set('client_cn', filter.clientCn);
    if (filter?.action) params.set('action', filter.action);
    if (filter?.startDate) params.set('start_date', filter.startDate);
    if (filter?.endDate) params.set('end_date', filter.endDate);

    const query = params.toString();
    const path = query ? `/v1/audit/export?${query}` : '/v1/audit/export';
    return this.http.get<AuditEntry[]>(path);
  }

  /**
   * Get aggregated audit statistics for the current tenant.
   * Returns total counts, success/failure breakdown, top actors and actions,
   * and recent failures.
   */
  async getStats(): Promise<AuditStats> {
    return this.http.get<AuditStats>('/v1/audit/stats');
  }
}
