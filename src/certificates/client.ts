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

export class CertificatesClient {
  constructor(private http: HttpClient) {}

  /**
   * Store a new certificate for custody.
   *
   * @param request - Certificate storage request
   * @param tenantId - Tenant ID (required if not in JWT)
   * @returns Certificate metadata
   *
   * @example
   * ```typescript
   * const cert = await client.certificates.store({
   *   clientId: 'B12345678',
   *   kind: 'AEAT',
   *   alias: 'firma-2024',
   *   certificateData: base64EncodedP12,
   *   certificateType: 'P12',
   *   passphrase: 'secret123',
   *   purpose: 'SIGNING',
   *   clientName: 'ACME Corp',
   *   contactEmail: 'admin@acme.com'
   * }, 'acme');
   * ```
   */
  async store(request: StoreCertificateRequest, tenantId?: string): Promise<Certificate> {
    const params = tenantId ? `?tenantId=${encodeURIComponent(tenantId)}` : '';
    return this.http.post<Certificate>(`/v1/certificates${params}`, request);
  }

  /**
   * Get certificate metadata by ID.
   *
   * @param id - Certificate ID
   * @param tenantId - Tenant ID (required if not in JWT)
   * @returns Certificate metadata
   */
  async get(id: string, tenantId?: string): Promise<Certificate> {
    const params = tenantId ? `?tenantId=${encodeURIComponent(tenantId)}` : '';
    return this.http.get<Certificate>(`/v1/certificates/${id}${params}`);
  }

  /**
   * Get certificate by business identity (clientId/kind/alias).
   *
   * @param clientId - External customer identifier (e.g., NIF/CIF)
   * @param kind - Certificate kind (AEAT, FNMT, CUSTOM, etc.)
   * @param alias - Human-readable identifier
   * @param tenantId - Tenant ID (required if not in JWT)
   * @returns Certificate metadata
   *
   * @example
   * ```typescript
   * const cert = await client.certificates.getByIdentity(
   *   'B12345678',
   *   'AEAT',
   *   'firma-2024',
   *   'acme'
   * );
   * ```
   */
  async getByIdentity(
    clientId: string,
    kind: string,
    alias: string,
    tenantId?: string
  ): Promise<Certificate> {
    const params = tenantId ? `?tenantId=${encodeURIComponent(tenantId)}` : '';
    const encodedClientId = encodeURIComponent(clientId);
    const encodedKind = encodeURIComponent(kind);
    const encodedAlias = encodeURIComponent(alias);
    return this.http.get<Certificate>(
      `/v1/certificates/by-identity/${encodedClientId}/${encodedKind}/${encodedAlias}${params}`
    );
  }

  /**
   * List certificates with optional filtering.
   *
   * @param filter - Filter options
   * @param tenantId - Tenant ID (required if not in JWT)
   * @returns Paginated list of certificates
   */
  async list(filter?: CertificateFilter, tenantId?: string): Promise<PaginatedResponse<Certificate>> {
    const params = new URLSearchParams();
    if (tenantId) params.set('tenantId', tenantId);
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

  /**
   * Get certificate statistics.
   *
   * @param tenantId - Tenant ID (required if not in JWT)
   * @returns Statistics including counts by status and kind
   */
  async getStats(tenantId?: string): Promise<CertificateStats> {
    const params = tenantId ? `?tenantId=${encodeURIComponent(tenantId)}` : '';
    return this.http.get<CertificateStats>(`/v1/certificates/stats${params}`);
  }

  /**
   * List certificates expiring within a specified number of days.
   *
   * @param days - Number of days to look ahead (default: 30)
   * @param tenantId - Tenant ID (required if not in JWT)
   * @returns Array of expiring certificates
   */
  async listExpiring(days?: number, tenantId?: string): Promise<Certificate[]> {
    const params = new URLSearchParams();
    if (tenantId) params.set('tenantId', tenantId);
    if (days !== undefined) params.set('days', days.toString());

    const query = params.toString();
    const path = query ? `/v1/certificates/expiring?${query}` : '/v1/certificates/expiring';
    return this.http.get<Certificate[]>(path);
  }

  /**
   * Update certificate metadata.
   *
   * @param id - Certificate ID
   * @param request - Update request
   * @param tenantId - Tenant ID (required if not in JWT)
   * @returns Updated certificate metadata
   */
  async update(
    id: string,
    request: UpdateCertificateRequest,
    tenantId?: string
  ): Promise<Certificate> {
    const params = tenantId ? `?tenantId=${encodeURIComponent(tenantId)}` : '';
    return this.http.patch<Certificate>(`/v1/certificates/${id}${params}`, request);
  }

  /**
   * Decrypt certificate (retrieve the actual certificate data).
   *
   * **Requires business justification** - the purpose is logged for audit.
   *
   * @param id - Certificate ID
   * @param purpose - Business justification for accessing the certificate
   * @param tenantId - Tenant ID (required if not in JWT)
   * @returns Decrypted certificate data (base64 encoded)
   *
   * @example
   * ```typescript
   * const decrypted = await client.certificates.decrypt(
   *   'cert-id-123',
   *   'Tax filing submission',
   *   'acme'
   * );
   * const certData = Buffer.from(decrypted.certificateData, 'base64');
   * ```
   */
  async decrypt(id: string, purpose: string, tenantId?: string): Promise<DecryptedCertificate> {
    const params = tenantId ? `?tenantId=${encodeURIComponent(tenantId)}` : '';
    return this.http.post<DecryptedCertificate>(`/v1/certificates/${id}/decrypt${params}`, {
      purpose,
    });
  }

  /**
   * Rotate certificate (replace with a new certificate).
   *
   * The old certificate is preserved in history.
   *
   * @param id - Certificate ID
   * @param request - Rotation request with new certificate data
   * @param tenantId - Tenant ID (required if not in JWT)
   * @returns Updated certificate metadata
   *
   * @example
   * ```typescript
   * const rotated = await client.certificates.rotate('cert-id-123', {
   *   certificateData: newBase64EncodedP12,
   *   certificateType: 'P12',
   *   passphrase: 'newSecret',
   *   reason: 'Annual renewal'
   * }, 'acme');
   * ```
   */
  async rotate(
    id: string,
    request: RotateCertificateRequest,
    tenantId?: string
  ): Promise<Certificate> {
    const params = tenantId ? `?tenantId=${encodeURIComponent(tenantId)}` : '';
    return this.http.post<Certificate>(`/v1/certificates/${id}/rotate${params}`, request);
  }

  /**
   * Delete a certificate.
   *
   * The underlying secret data is preserved for audit purposes.
   *
   * @param id - Certificate ID
   * @param tenantId - Tenant ID (required if not in JWT)
   */
  async delete(id: string, tenantId?: string): Promise<void> {
    const params = tenantId ? `?tenantId=${encodeURIComponent(tenantId)}` : '';
    await this.http.delete(`/v1/certificates/${id}${params}`);
  }

  /**
   * Get certificate access log.
   *
   * @param id - Certificate ID
   * @param limit - Maximum number of entries to return (default: 100)
   * @param tenantId - Tenant ID (required if not in JWT)
   * @returns Access log entries
   */
  async getAccessLog(
    id: string,
    limit?: number,
    tenantId?: string
  ): Promise<CertificateAccessLog> {
    const params = new URLSearchParams();
    if (tenantId) params.set('tenantId', tenantId);
    if (limit !== undefined) params.set('limit', limit.toString());

    const query = params.toString();
    const path = query
      ? `/v1/certificates/${id}/access-log?${query}`
      : `/v1/certificates/${id}/access-log`;
    return this.http.get<CertificateAccessLog>(path);
  }

  // ============================================================================
  // Convenience Methods
  // ============================================================================

  /**
   * Store a P12 certificate with simplified parameters.
   *
   * @example
   * ```typescript
   * const cert = await client.certificates.storeP12({
   *   clientId: 'B12345678',
   *   kind: 'AEAT',
   *   alias: 'firma-2024',
   *   p12Data: fs.readFileSync('cert.p12'),
   *   passphrase: 'secret',
   *   purpose: 'SIGNING',
   *   clientName: 'ACME Corp'
   * }, 'acme');
   * ```
   */
  async storeP12(
    options: {
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
    },
    tenantId?: string
  ): Promise<Certificate> {
    const certificateData = Buffer.isBuffer(options.p12Data)
      ? options.p12Data.toString('base64')
      : options.p12Data;

    return this.store(
      {
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
      },
      tenantId
    );
  }

  /**
   * Store a PEM certificate with simplified parameters.
   */
  async storePEM(
    options: {
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
    },
    tenantId?: string
  ): Promise<Certificate> {
    const certificateData = Buffer.isBuffer(options.pemData)
      ? options.pemData.toString('base64')
      : options.pemData;

    return this.store(
      {
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
      },
      tenantId
    );
  }

  /**
   * List certificates by client ID.
   */
  async listByClient(
    clientId: string,
    tenantId?: string,
    options?: { limit?: number; offset?: number }
  ): Promise<PaginatedResponse<Certificate>> {
    return this.list(
      {
        clientId,
        limit: options?.limit,
        offset: options?.offset,
      },
      tenantId
    );
  }

  /**
   * List certificates by kind (AEAT, FNMT, CUSTOM, etc.).
   */
  async listByKind(
    kind: string,
    tenantId?: string,
    options?: { limit?: number; offset?: number }
  ): Promise<PaginatedResponse<Certificate>> {
    return this.list(
      {
        kind,
        limit: options?.limit,
        offset: options?.offset,
      },
      tenantId
    );
  }

  /**
   * List active certificates only.
   */
  async listActive(
    tenantId?: string,
    options?: { limit?: number; offset?: number }
  ): Promise<PaginatedResponse<Certificate>> {
    return this.list(
      {
        status: 'ACTIVE',
        limit: options?.limit,
        offset: options?.offset,
      },
      tenantId
    );
  }

  /**
   * List expired certificates only.
   */
  async listExpired(
    tenantId?: string,
    options?: { limit?: number; offset?: number }
  ): Promise<PaginatedResponse<Certificate>> {
    return this.list(
      {
        status: 'EXPIRED',
        limit: options?.limit,
        offset: options?.offset,
      },
      tenantId
    );
  }

  /**
   * Download certificate as Buffer.
   *
   * @param id - Certificate ID
   * @param purpose - Business justification
   * @param tenantId - Tenant ID
   * @returns Certificate data as Buffer
   */
  async download(id: string, purpose: string, tenantId?: string): Promise<Buffer> {
    const decrypted = await this.decrypt(id, purpose, tenantId);
    return Buffer.from(decrypted.certificateData, 'base64');
  }
}
