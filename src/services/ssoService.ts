/**
 * SSO Service - API client for SSO endpoints
 *
 * Provides methods for SSO authentication, tokens, roles, permissions, teams
 */

// =============================================================================
// Types
// =============================================================================

export interface SsoUser {
  id: number;
  console_user_id: number;
  email: string;
  name: string;
}

export interface Organization {
  id: number;
  slug: string;
  name: string;
  role: string;
}

export interface Role {
  id: number;
  name: string;
  slug: string;
  description: string | null;
  level: number;
  permissions_count?: number;
  created_at: string;
  updated_at: string;
}

export interface Permission {
  id: number;
  name: string;
  slug: string;
  group: string | null;
  description?: string | null;
  roles_count?: number;
  created_at: string;
  updated_at: string;
}

export interface RoleWithPermissions extends Role {
  permissions: Permission[];
}

export interface PermissionMatrix {
  roles: Pick<Role, "id" | "slug" | "name">[];
  permissions: Record<string, Pick<Permission, "id" | "slug" | "name">[]>;
  matrix: Record<string, string[]>; // role_slug: permission_slugs[]
}

export interface ApiToken {
  id: number;
  name: string;
  last_used_at: string | null;
  created_at: string;
  is_current: boolean;
}

export interface TeamWithPermissions {
  console_team_id: number;
  name: string;
  path: string | null;
  permissions: Pick<Permission, "id" | "slug">[];
}

export interface TeamPermissionDetail {
  console_team_id: number;
  permissions: Pick<Permission, "id" | "slug" | "name">[];
}

export interface OrphanedTeam {
  console_team_id: number;
  permissions_count: number;
  permissions: string[];
  deleted_at: string | null;
}

// Input types
export interface SsoCallbackInput {
  code: string;
  device_name?: string;
}

export interface CreateRoleInput {
  slug: string;
  name: string;
  level: number;
  description?: string;
}

export interface UpdateRoleInput {
  name?: string;
  level?: number;
  description?: string | null;
}

export interface CreatePermissionInput {
  slug: string;
  name: string;
  group?: string;
  description?: string;
}

export interface UpdatePermissionInput {
  name?: string;
  group?: string | null;
  description?: string | null;
}

export interface SyncPermissionsInput {
  permissions: (number | string)[];
}

export interface CleanupOrphanedInput {
  console_team_id?: number;
  older_than_days?: number;
}

// =============================================================================
// Helper functions
// =============================================================================

/**
 * Get XSRF token from cookie (for Sanctum CSRF protection)
 */
function getXsrfToken(): string | undefined {
  if (typeof document === "undefined") return undefined;
  return document.cookie
    .split("; ")
    .find((row) => row.startsWith("XSRF-TOKEN="))
    ?.split("=")[1];
}

/**
 * Build headers with XSRF token and optional org slug
 */
function buildHeaders(orgSlug?: string): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };

  const xsrfToken = getXsrfToken();
  if (xsrfToken) {
    headers["X-XSRF-TOKEN"] = decodeURIComponent(xsrfToken);
  }

  if (orgSlug) {
    headers["X-Org-Slug"] = orgSlug;
  }

  return headers;
}

/**
 * Fetch CSRF cookie from backend
 */
async function csrf(apiUrl: string): Promise<void> {
  await fetch(`${apiUrl}/sanctum/csrf-cookie`, {
    credentials: "include",
  });
}

/**
 * Make API request with proper error handling
 */
async function request<T>(
  apiUrl: string,
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetch(`${apiUrl}${path}`, {
    ...options,
    credentials: "include",
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || `HTTP ${response.status}`);
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return undefined as T;
  }

  return response.json();
}

// =============================================================================
// Service Factory
// =============================================================================

export interface SsoServiceConfig {
  apiUrl: string;
}

export function createSsoService(config: SsoServiceConfig) {
  const { apiUrl } = config;

  return {
    // =========================================================================
    // SSO Auth
    // =========================================================================

    /**
     * Exchange SSO authorization code for tokens
     * POST /api/sso/callback
     */
    callback: async (
      input: SsoCallbackInput
    ): Promise<{
      user: SsoUser;
      organizations: Organization[];
      token?: string;
    }> => {
      await csrf(apiUrl);
      return request(apiUrl, "/api/sso/callback", {
        method: "POST",
        headers: buildHeaders(),
        body: JSON.stringify(input),
      });
    },

    /**
     * Logout current user and revoke tokens
     * POST /api/sso/logout
     */
    logout: async (): Promise<{ message: string }> => {
      return request(apiUrl, "/api/sso/logout", {
        method: "POST",
        headers: buildHeaders(),
      });
    },

    /**
     * Get current authenticated user with organizations
     * GET /api/sso/user
     */
    getUser: async (): Promise<{
      user: SsoUser;
      organizations: Organization[];
    }> => {
      return request(apiUrl, "/api/sso/user", {
        headers: buildHeaders(),
      });
    },

    /**
     * Get Console SSO global logout URL
     * GET /api/sso/global-logout-url
     */
    getGlobalLogoutUrl: async (
      redirectUri?: string
    ): Promise<{ logout_url: string }> => {
      const params = redirectUri
        ? `?redirect_uri=${encodeURIComponent(redirectUri)}`
        : "";
      return request(apiUrl, `/api/sso/global-logout-url${params}`, {
        headers: buildHeaders(),
      });
    },

    // =========================================================================
    // SSO Tokens (for mobile apps)
    // =========================================================================

    /**
     * List all API tokens for current user
     * GET /api/sso/tokens
     */
    getTokens: async (): Promise<{ tokens: ApiToken[] }> => {
      return request(apiUrl, "/api/sso/tokens", {
        headers: buildHeaders(),
      });
    },

    /**
     * Revoke a specific token
     * DELETE /api/sso/tokens/{tokenId}
     */
    revokeToken: async (tokenId: number): Promise<{ message: string }> => {
      return request(apiUrl, `/api/sso/tokens/${tokenId}`, {
        method: "DELETE",
        headers: buildHeaders(),
      });
    },

    /**
     * Revoke all tokens except current
     * POST /api/sso/tokens/revoke-others
     */
    revokeOtherTokens: async (): Promise<{
      message: string;
      revoked_count: number;
    }> => {
      return request(apiUrl, "/api/sso/tokens/revoke-others", {
        method: "POST",
        headers: buildHeaders(),
      });
    },

    // =========================================================================
    // Roles (Read-only for authenticated users)
    // =========================================================================

    /**
     * Get all roles
     * GET /api/sso/roles
     */
    getRoles: async (): Promise<{ data: Role[] }> => {
      return request(apiUrl, "/api/sso/roles", {
        headers: buildHeaders(),
      });
    },

    /**
     * Get single role with permissions
     * GET /api/sso/roles/{id}
     */
    getRole: async (id: number): Promise<{ data: RoleWithPermissions }> => {
      return request(apiUrl, `/api/sso/roles/${id}`, {
        headers: buildHeaders(),
      });
    },

    // =========================================================================
    // Permissions (Read-only for authenticated users)
    // =========================================================================

    /**
     * Get all permissions
     * GET /api/sso/permissions
     */
    getPermissions: async (params?: {
      group?: string;
      search?: string;
      grouped?: boolean;
    }): Promise<{ data: Permission[]; groups: string[] }> => {
      const queryString = params
        ? `?${new URLSearchParams(
            Object.entries(params)
              .filter(([, v]) => v !== undefined)
              .map(([k, v]) => [k, String(v)])
          )}`
        : "";
      return request(apiUrl, `/api/sso/permissions${queryString}`, {
        headers: buildHeaders(),
      });
    },

    /**
     * Get permission matrix (roles x permissions)
     * GET /api/sso/permission-matrix
     */
    getPermissionMatrix: async (): Promise<PermissionMatrix> => {
      return request(apiUrl, "/api/sso/permission-matrix", {
        headers: buildHeaders(),
      });
    },

    // =========================================================================
    // Admin - Roles (requires admin role + org context)
    // =========================================================================

    /**
     * List all roles (admin)
     * GET /api/admin/sso/roles
     */
    adminGetRoles: async (orgSlug: string): Promise<{ data: Role[] }> => {
      return request(apiUrl, "/api/admin/sso/roles", {
        headers: buildHeaders(orgSlug),
      });
    },

    /**
     * Get single role (admin)
     * GET /api/admin/sso/roles/{id}
     */
    adminGetRole: async (
      id: number,
      orgSlug: string
    ): Promise<{ data: RoleWithPermissions }> => {
      return request(apiUrl, `/api/admin/sso/roles/${id}`, {
        headers: buildHeaders(orgSlug),
      });
    },

    /**
     * Create role (admin only)
     * POST /api/admin/sso/roles
     */
    createRole: async (
      input: CreateRoleInput,
      orgSlug: string
    ): Promise<{ data: Role; message: string }> => {
      return request(apiUrl, "/api/admin/sso/roles", {
        method: "POST",
        headers: buildHeaders(orgSlug),
        body: JSON.stringify(input),
      });
    },

    /**
     * Update role (admin only)
     * PUT /api/admin/sso/roles/{id}
     */
    updateRole: async (
      id: number,
      input: UpdateRoleInput,
      orgSlug: string
    ): Promise<{ data: Role; message: string }> => {
      return request(apiUrl, `/api/admin/sso/roles/${id}`, {
        method: "PUT",
        headers: buildHeaders(orgSlug),
        body: JSON.stringify(input),
      });
    },

    /**
     * Delete role (admin only)
     * DELETE /api/admin/sso/roles/{id}
     */
    deleteRole: async (id: number, orgSlug: string): Promise<void> => {
      return request(apiUrl, `/api/admin/sso/roles/${id}`, {
        method: "DELETE",
        headers: buildHeaders(orgSlug),
      });
    },

    /**
     * Get role's permissions (admin)
     * GET /api/admin/sso/roles/{id}/permissions
     */
    getRolePermissions: async (
      id: number,
      orgSlug: string
    ): Promise<{
      role: Pick<Role, "id" | "slug" | "name">;
      permissions: Permission[];
    }> => {
      return request(apiUrl, `/api/admin/sso/roles/${id}/permissions`, {
        headers: buildHeaders(orgSlug),
      });
    },

    /**
     * Sync role's permissions (admin)
     * PUT /api/admin/sso/roles/{id}/permissions
     */
    syncRolePermissions: async (
      id: number,
      input: SyncPermissionsInput,
      orgSlug: string
    ): Promise<{ message: string; attached: number; detached: number }> => {
      return request(apiUrl, `/api/admin/sso/roles/${id}/permissions`, {
        method: "PUT",
        headers: buildHeaders(orgSlug),
        body: JSON.stringify(input),
      });
    },

    // =========================================================================
    // Admin - Permissions (requires admin role + org context)
    // =========================================================================

    /**
     * List all permissions (admin)
     * GET /api/admin/sso/permissions
     */
    adminGetPermissions: async (
      orgSlug: string,
      params?: { group?: string; search?: string; grouped?: boolean }
    ): Promise<{ data: Permission[]; groups: string[] }> => {
      const queryString = params
        ? `?${new URLSearchParams(
            Object.entries(params)
              .filter(([, v]) => v !== undefined)
              .map(([k, v]) => [k, String(v)])
          )}`
        : "";
      return request(apiUrl, `/api/admin/sso/permissions${queryString}`, {
        headers: buildHeaders(orgSlug),
      });
    },

    /**
     * Get single permission (admin)
     * GET /api/admin/sso/permissions/{id}
     */
    adminGetPermission: async (
      id: number,
      orgSlug: string
    ): Promise<{ data: Permission }> => {
      return request(apiUrl, `/api/admin/sso/permissions/${id}`, {
        headers: buildHeaders(orgSlug),
      });
    },

    /**
     * Create permission (admin only)
     * POST /api/admin/sso/permissions
     */
    createPermission: async (
      input: CreatePermissionInput,
      orgSlug: string
    ): Promise<{ data: Permission; message: string }> => {
      return request(apiUrl, "/api/admin/sso/permissions", {
        method: "POST",
        headers: buildHeaders(orgSlug),
        body: JSON.stringify(input),
      });
    },

    /**
     * Update permission (admin only)
     * PUT /api/admin/sso/permissions/{id}
     */
    updatePermission: async (
      id: number,
      input: UpdatePermissionInput,
      orgSlug: string
    ): Promise<{ data: Permission; message: string }> => {
      return request(apiUrl, `/api/admin/sso/permissions/${id}`, {
        method: "PUT",
        headers: buildHeaders(orgSlug),
        body: JSON.stringify(input),
      });
    },

    /**
     * Delete permission (admin only)
     * DELETE /api/admin/sso/permissions/{id}
     */
    deletePermission: async (id: number, orgSlug: string): Promise<void> => {
      return request(apiUrl, `/api/admin/sso/permissions/${id}`, {
        method: "DELETE",
        headers: buildHeaders(orgSlug),
      });
    },

    /**
     * Get permission matrix (admin)
     * GET /api/admin/sso/permission-matrix
     */
    adminGetPermissionMatrix: async (
      orgSlug: string
    ): Promise<PermissionMatrix> => {
      return request(apiUrl, "/api/admin/sso/permission-matrix", {
        headers: buildHeaders(orgSlug),
      });
    },

    // =========================================================================
    // Admin - Team Permissions (requires admin role + org context)
    // =========================================================================

    /**
     * Get all teams with their permissions (admin only)
     * GET /api/admin/sso/teams/permissions
     */
    getTeamPermissions: async (
      orgSlug: string
    ): Promise<{ teams: TeamWithPermissions[] }> => {
      return request(apiUrl, "/api/admin/sso/teams/permissions", {
        headers: buildHeaders(orgSlug),
      });
    },

    /**
     * Get specific team permissions (admin only)
     * GET /api/admin/sso/teams/{teamId}/permissions
     */
    getTeamPermission: async (
      teamId: number,
      orgSlug: string
    ): Promise<TeamPermissionDetail> => {
      return request(apiUrl, `/api/admin/sso/teams/${teamId}/permissions`, {
        headers: buildHeaders(orgSlug),
      });
    },

    /**
     * Sync team permissions (admin only)
     * PUT /api/admin/sso/teams/{teamId}/permissions
     */
    syncTeamPermissions: async (
      teamId: number,
      input: SyncPermissionsInput,
      orgSlug: string
    ): Promise<{
      message: string;
      console_team_id: number;
      attached: number;
      detached: number;
    }> => {
      return request(apiUrl, `/api/admin/sso/teams/${teamId}/permissions`, {
        method: "PUT",
        headers: buildHeaders(orgSlug),
        body: JSON.stringify(input),
      });
    },

    /**
     * Remove all permissions for a team (admin only)
     * DELETE /api/admin/sso/teams/{teamId}/permissions
     */
    removeTeamPermissions: async (
      teamId: number,
      orgSlug: string
    ): Promise<void> => {
      return request(apiUrl, `/api/admin/sso/teams/${teamId}/permissions`, {
        method: "DELETE",
        headers: buildHeaders(orgSlug),
      });
    },

    // =========================================================================
    // Admin - Orphaned Team Permissions (requires admin role + org context)
    // =========================================================================

    /**
     * List orphaned team permissions (admin only)
     * GET /api/admin/sso/teams/orphaned
     */
    getOrphanedTeamPermissions: async (
      orgSlug: string
    ): Promise<{
      orphaned_teams: OrphanedTeam[];
      total_orphaned_permissions: number;
    }> => {
      return request(apiUrl, "/api/admin/sso/teams/orphaned", {
        headers: buildHeaders(orgSlug),
      });
    },

    /**
     * Restore orphaned team permissions (admin only)
     * POST /api/admin/sso/teams/orphaned/{teamId}/restore
     */
    restoreOrphanedTeamPermissions: async (
      teamId: number,
      orgSlug: string
    ): Promise<{
      message: string;
      console_team_id: number;
      restored_count: number;
    }> => {
      return request(apiUrl, `/api/admin/sso/teams/orphaned/${teamId}/restore`, {
        method: "POST",
        headers: buildHeaders(orgSlug),
      });
    },

    /**
     * Cleanup orphaned team permissions (admin only)
     * DELETE /api/admin/sso/teams/orphaned
     */
    cleanupOrphanedTeamPermissions: async (
      orgSlug: string,
      input?: CleanupOrphanedInput
    ): Promise<{ message: string; deleted_count: number }> => {
      return request(apiUrl, "/api/admin/sso/teams/orphaned", {
        method: "DELETE",
        headers: buildHeaders(orgSlug),
        body: input ? JSON.stringify(input) : undefined,
      });
    },
  };
}

// Export types
export type SsoService = ReturnType<typeof createSsoService>;
