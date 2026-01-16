/**
 * SSO Query Keys - For TanStack Query / React Query
 *
 * Centralized key management for SSO-related queries
 */

export const ssoQueryKeys = {
  all: ["sso"] as const,

  // SSO Auth
  auth: {
    all: () => [...ssoQueryKeys.all, "auth"] as const,
    user: () => [...ssoQueryKeys.auth.all(), "user"] as const,
    globalLogoutUrl: (redirectUri?: string) =>
      [...ssoQueryKeys.auth.all(), "global-logout-url", redirectUri] as const,
  },

  // SSO Tokens
  tokens: {
    all: () => [...ssoQueryKeys.all, "tokens"] as const,
    list: () => [...ssoQueryKeys.tokens.all(), "list"] as const,
  },

  // Roles (read-only)
  roles: {
    all: () => [...ssoQueryKeys.all, "roles"] as const,
    list: () => [...ssoQueryKeys.roles.all(), "list"] as const,
    detail: (id: number) => [...ssoQueryKeys.roles.all(), "detail", id] as const,
  },

  // Permissions (read-only)
  permissions: {
    all: () => [...ssoQueryKeys.all, "permissions"] as const,
    list: (params?: { group?: string; search?: string; grouped?: boolean }) =>
      [...ssoQueryKeys.permissions.all(), "list", params] as const,
    matrix: () => [...ssoQueryKeys.permissions.all(), "matrix"] as const,
  },

  // Admin - Roles
  adminRoles: {
    all: (orgSlug: string) => [...ssoQueryKeys.all, "admin", orgSlug, "roles"] as const,
    list: (orgSlug: string) => [...ssoQueryKeys.adminRoles.all(orgSlug), "list"] as const,
    detail: (orgSlug: string, id: number) =>
      [...ssoQueryKeys.adminRoles.all(orgSlug), "detail", id] as const,
    permissions: (orgSlug: string, id: number) =>
      [...ssoQueryKeys.adminRoles.all(orgSlug), id, "permissions"] as const,
  },

  // Admin - Permissions
  adminPermissions: {
    all: (orgSlug: string) => [...ssoQueryKeys.all, "admin", orgSlug, "permissions"] as const,
    list: (orgSlug: string, params?: { group?: string; search?: string; grouped?: boolean }) =>
      [...ssoQueryKeys.adminPermissions.all(orgSlug), "list", params] as const,
    detail: (orgSlug: string, id: number) =>
      [...ssoQueryKeys.adminPermissions.all(orgSlug), "detail", id] as const,
    matrix: (orgSlug: string) =>
      [...ssoQueryKeys.adminPermissions.all(orgSlug), "matrix"] as const,
  },

  // Admin - Teams
  adminTeams: {
    all: (orgSlug: string) => [...ssoQueryKeys.all, "admin", orgSlug, "teams"] as const,
    permissions: (orgSlug: string) =>
      [...ssoQueryKeys.adminTeams.all(orgSlug), "permissions"] as const,
    teamPermissions: (orgSlug: string, teamId: number) =>
      [...ssoQueryKeys.adminTeams.all(orgSlug), teamId, "permissions"] as const,
    orphaned: (orgSlug: string) =>
      [...ssoQueryKeys.adminTeams.all(orgSlug), "orphaned"] as const,
  },
} as const;
