import { SetMetadata } from '@nestjs/common';

export const REQUIRE_TENANT_KEY = 'requireTenant';

/**
 * @RequireTenant() — route/controller decorator for strict tenant isolation.
 *
 * Responsibility: Marks an endpoint as strictly requiring a multi-tenant context.
 * Used in conjunction with `TenantGuard` to enforce that a valid `tenantId` is
 * present in the active request (either implicitly via the user's JWT, or explicitly
 * via an impersonation header for SUPER_ADMINs).
 *
 * Usage:
 *  @Get('company-data')
 *  @RequireTenant()
 *  async getCompanyData() { ... }
 */
export const RequireTenant = () => SetMetadata(REQUIRE_TENANT_KEY, true);
