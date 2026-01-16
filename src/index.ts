// Context & Provider
export { SsoContext } from './context/SsoContext';
export { SsoProvider } from './context/SsoProvider';

// Hooks
export { useAuth } from './hooks/useAuth';
export { useOrganization } from './hooks/useOrganization';
export { useSso } from './hooks/useSso';

// Components
export { SsoCallback } from './components/SsoCallback';
export { OrganizationSwitcher } from './components/OrganizationSwitcher';
export { ProtectedRoute } from './components/ProtectedRoute';

// Services
export { createSsoService } from './services';
export type {
    SsoService,
    SsoServiceConfig,
    // Service types (snake_case - matches API)
    SsoUser as SsoServiceUser,
    Organization,
    Role,
    Permission,
    RoleWithPermissions,
    PermissionMatrix,
    ApiToken,
    TeamWithPermissions,
    TeamPermissionDetail,
    OrphanedTeam,
    // Input types
    SsoCallbackInput,
    CreateRoleInput,
    UpdateRoleInput,
    CreatePermissionInput,
    UpdatePermissionInput,
    SyncPermissionsInput,
    CleanupOrphanedInput,
} from './services';

// Types (camelCase - for React components)
export type {
    SsoUser,
    SsoOrganization,
    SsoConfig,
    SsoContextValue,
    SsoCallbackResponse,
    SsoProviderProps,
    SsoCallbackProps,
    OrganizationSwitcherProps,
    ProtectedRouteProps,
} from './types';

// Hook return types
export type { UseAuthReturn } from './hooks/useAuth';
export type { UseOrganizationReturn } from './hooks/useOrganization';
export type { UseSsoReturn } from './hooks/useSso';

// Query Keys (for TanStack Query / React Query)
export { ssoQueryKeys } from './queryKeys';
