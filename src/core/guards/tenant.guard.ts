import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role } from '@prisma/client';
import { AuthenticatedRequest } from '../../shared/types/request.interface';
import { RequestContext } from '../../shared/context/request-context';
import { REQUIRE_TENANT_KEY } from '../decorators/tenant.decorator';

/**
 * TenantGuard — multi-tenant access control guard.
 *
 * Responsibility: Bridges Authentication (JWT) and Multi-Tenancy (Data Isolation).
 * It intercepts the request after identity is verified, extracts the user's
 * `tenantId`, and injects it into the global `RequestContext` so downstream
 * ORM extensions (PrismaService) can automatically filter data.
 *
 * canActivate flow:
 * 1. Read @RequireTenant() metadata from handler/class via Reflector.
 * 2. Extract req.user from the authenticated request (set by JwtAuthGuard).
 * 3. Read `req.user.tenantId`. If the user is a global SUPER_ADMIN, they can
 *    optionally impersonate a tenant by passing the `x-tenant-id` header.
 * 4. Patch the `RequestContext` with the resolved `tenantId`.
 * 5. If @RequireTenant() is true but no `tenantId` could be resolved, throw 403.
 *
 * SOLID Principles:
 * - Single Responsibility: Only handles tenant context resolution and enforcement.
 * - Dependency Inversion: Relies on `RequestContext` abstraction, not concrete DB logic.
 *
 * Dependencies:
 *  - @RequireTenant() : src/core/decorators/tenant.decorator.ts
 *  - RequestContext   : src/shared/context/request-context.ts
 */
@Injectable()
export class TenantGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const isTenantRequired = this.reflector.getAllAndOverride<boolean>(REQUIRE_TENANT_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const { user } = request;

    if (!user) {
      // Should not happen if JwtAuthGuard is applied first, but as a safeguard:
      return true;
    }

    let activeTenantId = user.tenantId;

    // SUPER_ADMINs can optionally impersonate a tenant via header
    if (user.role === Role.SUPER_ADMIN && !activeTenantId) {
      const headerTenantId = request.headers['x-tenant-id'];
      if (typeof headerTenantId === 'string' && headerTenantId.trim() !== '') {
        activeTenantId = headerTenantId.trim();
      }
    }

    // Set the tenant ID in the request context for Prisma Extension to use
    if (activeTenantId) {
      RequestContext.patch({ tenantId: activeTenantId });
    }

    // If route requires a tenant and we don't have one, reject
    if (isTenantRequired && !activeTenantId) {
      throw new ForbiddenException({
        name: 'ForbiddenError',
        code: 'ERR_TENANT_REQUIRED',
        message: 'This action requires a valid tenant context.',
      });
    }

    return true;
  }
}
