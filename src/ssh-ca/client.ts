// Path: zn-vault-sdk-node/src/ssh-ca/client.ts

import type { HttpClient } from '../http/client.js';
import type {
  SignSshCertificateRequest,
  SignSshCertificateResponse,
  SshCaPublicKey,
  SshCaInfo,
  SshCa,
  InitSshCaRequest,
  SshPrincipalMapping,
  CreateSshPrincipalMappingRequest,
  UpdateSshPrincipalMappingRequest,
  SshServerGroup,
  SshServerGroupDetail,
  SshServerGroupAccessRule,
  CreateSshServerGroupRequest,
  SshCertificate,
  SshCertificateDetail,
  SshCertificateFilter,
  PaginatedResponse,
} from '../types/index.js';

/**
 * SSH Certificate Authority operations: sign OpenSSH user certificates, manage
 * the tenant CA, principal mappings, server groups, and issued-certificate
 * records.
 *
 * Tenant is always derived from the authenticated principal by the server;
 * there are no client-supplied tenant parameters on the authenticated methods.
 * The unauthenticated CA-discovery helpers (`getCaPublicKey`, `getCaPublicKeyRaw`,
 * `getKrl`) take an explicit `tenant` because they map to public routes used for
 * server-side `sshd` configuration.
 *
 * The {@link sign} response's `certificate` is a raw OpenSSH certificate string,
 * suitable for passing straight to the `ssh2` library's `ConnectConfig.certificate`.
 */
export class SSHCAClient {
  constructor(private http: HttpClient) {}

  // ==========================================================================
  // Signing
  // ==========================================================================

  /**
   * Sign an SSH user public key into a short-lived OpenSSH certificate.
   *
   * Supplying `principals` is an admin override and requires `SSH_CA_ADMIN`
   * permission or tenant admin-crypto access; otherwise the server resolves
   * principals from the caller's SSO group memberships.
   *
   * @param request - Public key plus optional TTL and admin principal override.
   * @returns The signed certificate (raw OpenSSH string) and its metadata.
   */
  async sign(request: SignSshCertificateRequest): Promise<SignSshCertificateResponse> {
    return this.http.post<SignSshCertificateResponse>('/v1/ssh/sign', {
      publicKey: request.publicKey,
      ttlSeconds: request.ttlSeconds,
      principals: request.principals,
    });
  }

  /**
   * Sign an SSH user public key and return only the raw OpenSSH certificate
   * string — the form the `ssh2` library accepts for cert-based auth.
   *
   * @param publicKey - The SSH user public key in OpenSSH format.
   * @param options - Optional admin principal override and TTL.
   * @returns The raw OpenSSH certificate string.
   */
  async signString(
    publicKey: string,
    options?: { principals?: string[]; ttlSeconds?: number }
  ): Promise<string> {
    const response = await this.sign({
      publicKey,
      principals: options?.principals,
      ttlSeconds: options?.ttlSeconds,
    });
    return response.certificate;
  }

  // ==========================================================================
  // Public CA discovery (unauthenticated; tenant in path)
  // ==========================================================================

  /** Get a tenant's SSH CA public key and fingerprint (public endpoint). */
  async getCaPublicKey(tenant: string): Promise<SshCaPublicKey> {
    return this.http.get<SshCaPublicKey>(
      `/v1/ssh/ca/${encodeURIComponent(tenant)}/public-key`
    );
  }

  /**
   * Get a tenant's SSH CA public key as a raw OpenSSH string (public endpoint),
   * e.g. for a `TrustedUserCAKeys` file.
   */
  async getCaPublicKeyRaw(tenant: string): Promise<string> {
    return this.http.get<string>(
      `/v1/ssh/ca/${encodeURIComponent(tenant)}/public-key/raw`
    );
  }

  /**
   * Get a tenant's OpenSSH Key Revocation List (public endpoint), e.g. for a
   * `RevokedKeys` file. Returns the raw KRL bytes.
   */
  async getKrl(tenant: string): Promise<Buffer> {
    const data = await this.http.get<string | Buffer>(
      `/v1/ssh/ca/${encodeURIComponent(tenant)}/krl`
    );
    return Buffer.isBuffer(data) ? data : Buffer.from(data ?? '', 'binary');
  }

  // ==========================================================================
  // CA lifecycle (tenant from JWT)
  // ==========================================================================

  /** Get the authenticated tenant's SSH CA status and configuration. */
  async getCa(): Promise<SshCaInfo> {
    return this.http.get<SshCaInfo>('/v1/ssh/ca');
  }

  /** Initialize the authenticated tenant's SSH CA. */
  async initCa(request?: InitSshCaRequest): Promise<SshCa> {
    return this.http.post<SshCa>('/v1/ssh/ca', {
      keyType: request?.keyType,
      defaultTtlSeconds: request?.defaultTtlSeconds,
      maxTtlSeconds: request?.maxTtlSeconds,
      allowedExtensions: request?.allowedExtensions,
    });
  }

  /** Delete the authenticated tenant's SSH CA. */
  async deleteCa(): Promise<void> {
    await this.http.delete('/v1/ssh/ca');
  }

  // ==========================================================================
  // Principal mappings (SSO group -> principals)
  // ==========================================================================

  /** List the tenant's SSO-group-to-principal mappings. */
  async listPrincipalMappings(): Promise<SshPrincipalMapping[]> {
    const response = await this.http.get<{ items: SshPrincipalMapping[] }>(
      '/v1/ssh/principal-mappings'
    );
    return response.items;
  }

  /** Create a principal mapping for an SSO group. */
  async createPrincipalMapping(
    request: CreateSshPrincipalMappingRequest
  ): Promise<SshPrincipalMapping> {
    return this.http.post<SshPrincipalMapping>('/v1/ssh/principal-mappings', {
      groupId: request.groupId,
      principals: request.principals,
    });
  }

  /** Replace the principals of an existing mapping. */
  async updatePrincipalMapping(
    mappingId: string,
    request: UpdateSshPrincipalMappingRequest
  ): Promise<void> {
    await this.http.put(`/v1/ssh/principal-mappings/${encodeURIComponent(mappingId)}`, {
      principals: request.principals,
    });
  }

  /** Delete a principal mapping. */
  async deletePrincipalMapping(mappingId: string): Promise<void> {
    await this.http.delete(`/v1/ssh/principal-mappings/${encodeURIComponent(mappingId)}`);
  }

  // ==========================================================================
  // Server groups + access rules
  // ==========================================================================

  /** List the tenant's server groups. */
  async listServerGroups(): Promise<SshServerGroup[]> {
    const response = await this.http.get<{ items: SshServerGroup[] }>(
      '/v1/ssh/server-groups'
    );
    return response.items;
  }

  /** Create a server group. */
  async createServerGroup(request: CreateSshServerGroupRequest): Promise<SshServerGroup> {
    return this.http.post<SshServerGroup>('/v1/ssh/server-groups', {
      name: request.name,
      description: request.description,
    });
  }

  /** Get a server group with its access rules. */
  async getServerGroup(groupId: string): Promise<SshServerGroupDetail> {
    return this.http.get<SshServerGroupDetail>(
      `/v1/ssh/server-groups/${encodeURIComponent(groupId)}`
    );
  }

  /** Delete a server group. */
  async deleteServerGroup(groupId: string): Promise<void> {
    await this.http.delete(`/v1/ssh/server-groups/${encodeURIComponent(groupId)}`);
  }

  /**
   * Upsert an access rule on a server group (maps a Linux user to the
   * principals allowed to authenticate as it).
   */
  async setServerGroupAccess(
    groupId: string,
    rule: SshServerGroupAccessRule
  ): Promise<SshServerGroupAccessRule> {
    return this.http.put<SshServerGroupAccessRule>(
      `/v1/ssh/server-groups/${encodeURIComponent(groupId)}/access`,
      {
        linuxUser: rule.linuxUser,
        allowedPrincipals: rule.allowedPrincipals,
      }
    );
  }

  /** Delete a server group's access rule for a given Linux user. */
  async deleteServerGroupAccess(groupId: string, linuxUser: string): Promise<void> {
    await this.http.delete(
      `/v1/ssh/server-groups/${encodeURIComponent(groupId)}/access/${encodeURIComponent(linuxUser)}`
    );
  }

  /**
   * Get a server group's content for an OpenSSH `AuthorizedPrincipalsFile`
   * (raw text, typically one principal per line).
   */
  async getAuthorizedPrincipals(groupId: string): Promise<string> {
    return this.http.get<string>(
      `/v1/ssh/server-groups/${encodeURIComponent(groupId)}/authorized-principals`
    );
  }

  // ==========================================================================
  // Issued certificate records
  // ==========================================================================

  /** List issued SSH certificates with optional filtering and pagination. */
  async listCertificates(
    filter?: SshCertificateFilter
  ): Promise<PaginatedResponse<SshCertificate>> {
    const params = new URLSearchParams();
    if (filter?.activeOnly !== undefined) params.set('activeOnly', String(filter.activeOnly));
    if (filter?.revoked !== undefined) params.set('revoked', String(filter.revoked));
    if (filter?.userId) params.set('userId', filter.userId);
    if (filter?.limit) params.set('limit', filter.limit.toString());
    if (filter?.offset) params.set('offset', filter.offset.toString());

    const query = params.toString();
    const path = query ? `/v1/ssh/certificates?${query}` : '/v1/ssh/certificates';
    return this.http.get<PaginatedResponse<SshCertificate>>(path);
  }

  /** Get a single issued SSH certificate record by ID. */
  async getCertificate(certificateId: string): Promise<SshCertificateDetail> {
    return this.http.get<SshCertificateDetail>(
      `/v1/ssh/certificates/${encodeURIComponent(certificateId)}`
    );
  }

  /** Revoke an issued SSH certificate. The serial is added to the CA's KRL. */
  async revokeCertificate(certificateId: string, reason?: string): Promise<void> {
    await this.http.post(
      `/v1/ssh/certificates/${encodeURIComponent(certificateId)}/revoke`,
      { reason }
    );
  }
}
