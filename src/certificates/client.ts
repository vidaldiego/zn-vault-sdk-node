// Path: zn-vault-sdk-node/src/certificates/client.ts

import type { HttpClient } from '../http/client.js';
import type {
  Certificate,
  DecryptedCertificate,
  StoreCertificateRequest,
  UpdateCertificateRequest,
  RotateCertificateRequest,
  CertificateFilter,
  CertificateStats,
  CertificateAccessLog,
  PaginatedResponse,
} from '../types/index.js';

/**
 * Certificate lifecycle management.
 *
 * Tenant is always derived from the authenticated principal by the server;
 * there are no client-supplied tenant parameters on this client. For
 * cross-tenant certificate operations, use ZnVaultSuperadminClient.
 */
export class CertificatesClient {
  constructor(private http: HttpClient) {}

  /** Store a new certificate for custody. */
  async store(request: StoreCertificateRequest): Promise<Certificate> {
    return this.http.post<Certificate>('/v1/certificates', request);
  }

  /** Get certificate metadata by ID. */
  async get(id: string): Promise<Certificate> {
    return this.http.get<Certificate>(`/v1/certificates/${id}`);
  }

  /** Get certificate by business identity (clientId/kind/alias). */
  async getByIdentity(
    clientId: string,
    kind: string,
    alias: string
  ): Promise<Certificate> {
    const encodedClientId = encodeURIComponent(clientId);
    const encodedKind = encodeURIComponent(kind);
    const encodedAlias = encodeURIComponent(alias);
    return this.http.get<Certificate>(
      `/v1/certificates/by-identity/${encodedClientId}/${encodedKind}/${encodedAlias}`
    );
  }

  /** List certificates with optional filtering. */
  async list(filter?: CertificateFilter): Promise<PaginatedResponse<Certificate>> {
    const params = new URLSearchParams();
    if (filter?.clientId) params.set('clientId', filter.clientId);
    if (filter?.kind) params.set('kind', filter.kind);
    if (filter?.status) params.set('status', filter.status);
    if (filter?.expiringBefore) params.set('expiringBefore', filter.expiringBefore);
    if (filter?.tags) params.set('tags', filter.tags.join(','));
    if (filter?.limit) params.set('limit', filter.limit.toString());
    if (filter?.offset) params.set('offset', filter.offset.toString());

    const query = params.toString();
    const path = query ? `/v1/certificates?${query}` : '/v1/certificates';
    return this.http.get<PaginatedResponse<Certificate>>(path);
  }

  /** Get certificate statistics. */
  async getStats(): Promise<CertificateStats> {
    return this.http.get<CertificateStats>('/v1/certificates/stats');
  }

  /** List certificates expiring within a specified number of days. */
  async listExpiring(days?: number): Promise<Certificate[]> {
    const path = days !== undefined
      ? `/v1/certificates/expiring?days=${days}`
      : '/v1/certificates/expiring';
    return this.http.get<Certificate[]>(path);
  }

  /** Update certificate metadata. */
  async update(id: string, request: UpdateCertificateRequest): Promise<Certificate> {
    return this.http.patch<Certificate>(`/v1/certificates/${id}`, request);
  }

  /**
   * Decrypt certificate (retrieve the actual certificate data).
   * Requires business justification — the purpose is logged for audit.
   */
  async decrypt(id: string, purpose: string): Promise<DecryptedCertificate> {
    return this.http.post<DecryptedCertificate>(`/v1/certificates/${id}/decrypt`, { purpose });
  }

  /**
   * Rotate certificate (replace with a new certificate).
   * The old certificate is preserved in history.
   */
  async rotate(id: string, request: RotateCertificateRequest): Promise<Certificate> {
    return this.http.post<Certificate>(`/v1/certificates/${id}/rotate`, request);
  }

  /**
   * Delete a certificate.
   * The underlying secret data is preserved for audit purposes.
   */
  async delete(id: string): Promise<void> {
    await this.http.delete(`/v1/certificates/${id}`);
  }

  /** Get certificate access log. */
  async getAccessLog(id: string, limit?: number): Promise<CertificateAccessLog> {
    const path = limit !== undefined
      ? `/v1/certificates/${id}/access-log?limit=${limit}`
      : `/v1/certificates/${id}/access-log`;
    return this.http.get<CertificateAccessLog>(path);
  }

  // ============================================================================
  // Convenience Methods
  // ============================================================================

  /** Store a P12 certificate with simplified parameters. */
  async storeP12(options: {
    clientId: string;
    kind: string;
    alias: string;
    p12Data: Buffer | string;
    passphrase: string;
    purpose: 'TLS' | 'mTLS' | 'SIGNING' | 'ENCRYPTION' | 'AUTHENTICATION';
    clientName?: string;
    organizationId?: string;
    contactEmail?: string;
    tags?: string[];
    metadata?: Record<string, unknown>;
  }): Promise<Certificate> {
    const certificateData = Buffer.isBuffer(options.p12Data)
      ? options.p12Data.toString('base64')
      : options.p12Data;

    return this.store({
      clientId: options.clientId,
      kind: options.kind,
      alias: options.alias,
      certificateData,
      certificateType: 'P12',
      passphrase: options.passphrase,
      purpose: options.purpose,
      clientName: options.clientName,
      organizationId: options.organizationId,
      contactEmail: options.contactEmail,
      tags: options.tags,
      metadata: options.metadata,
    });
  }

  /** Store a PEM certificate with simplified parameters. */
  async storePEM(options: {
    clientId: string;
    kind: string;
    alias: string;
    pemData: Buffer | string;
    purpose: 'TLS' | 'mTLS' | 'SIGNING' | 'ENCRYPTION' | 'AUTHENTICATION';
    clientName?: string;
    organizationId?: string;
    contactEmail?: string;
    tags?: string[];
    metadata?: Record<string, unknown>;
  }): Promise<Certificate> {
    const certificateData = Buffer.isBuffer(options.pemData)
      ? options.pemData.toString('base64')
      : options.pemData;

    return this.store({
      clientId: options.clientId,
      kind: options.kind,
      alias: options.alias,
      certificateData,
      certificateType: 'PEM',
      purpose: options.purpose,
      clientName: options.clientName,
      organizationId: options.organizationId,
      contactEmail: options.contactEmail,
      tags: options.tags,
      metadata: options.metadata,
    });
  }

  /** List certificates by client ID. */
  async listByClient(
    clientId: string,
    options?: { limit?: number; offset?: number }
  ): Promise<PaginatedResponse<Certificate>> {
    return this.list({
      clientId,
      limit: options?.limit,
      offset: options?.offset,
    });
  }

  /** List certificates by kind (AEAT, FNMT, CUSTOM, etc.). */
  async listByKind(
    kind: string,
    options?: { limit?: number; offset?: number }
  ): Promise<PaginatedResponse<Certificate>> {
    return this.list({
      kind,
      limit: options?.limit,
      offset: options?.offset,
    });
  }

  /** List active certificates only. */
  async listActive(
    options?: { limit?: number; offset?: number }
  ): Promise<PaginatedResponse<Certificate>> {
    return this.list({
      status: 'ACTIVE',
      limit: options?.limit,
      offset: options?.offset,
    });
  }

  /** List expired certificates only. */
  async listExpired(
    options?: { limit?: number; offset?: number }
  ): Promise<PaginatedResponse<Certificate>> {
    return this.list({
      status: 'EXPIRED',
      limit: options?.limit,
      offset: options?.offset,
    });
  }

  /** Download certificate as Buffer. */
  async download(id: string, purpose: string): Promise<Buffer> {
    const decrypted = await this.decrypt(id, purpose);
    return Buffer.from(decrypted.certificateData, 'base64');
  }
}
