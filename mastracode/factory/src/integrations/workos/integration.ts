import type { ApiRoute } from '@mastra/core/server';
import { registerApiRoute } from '@mastra/core/server';
import type { Context } from 'hono';

import type { AuditEventRow } from '../../storage/domains/audit/base.js';
import type { FactoryIntegration, IntegrationContext } from '../base.js';

const UNKNOWN_LOCATION = 'unknown';

/**
 * WorkOS's portal intent for the audit-log section, as the wire value.
 *
 * `@workos-inc/node` exports this as `GeneratePortalLinkIntent.AuditLogs`, a
 * string enum member whose value is exactly this. Naming the value rather than
 * the enum is what lets this module take the client from its host instead of
 * importing a WorkOS package to reach a constant — and the client's own typings
 * still check the call, because the host passes a real WorkOS client.
 */
const AUDIT_LOGS_PORTAL_INTENT = 'audit_logs';

/** An audit event in the shape WorkOS's `auditLogs.createEvent` accepts. */
export interface WorkOSAuditEvent {
  action: string;
  occurredAt: Date;
  actor: { type: string; id: string };
  targets: Array<{ type: string; id: string; name?: string }>;
  context: { location: string; userAgent?: string };
  metadata: Record<string, string | number | boolean>;
}

/**
 * The slice of a WorkOS SDK client this integration uses.
 *
 * Structural on purpose, and this is the whole reason `@mastra/factory` no
 * longer depends on `@mastra/auth-workos`.
 *
 * The client was always the host's to supply — it arrives through the
 * constructor, like every other integration's — so the only thing the vendor
 * package was providing here was a name for its type and a thirty-line wrapper
 * around one `portal.generateLink` call. That put a WorkOS *auth provider*
 * package in the dependency list of a package whose auth module is deliberately
 * provider-neutral, and it put an unconditional `import '@mastra/auth-workos'`
 * in published output for a module most deployments never construct. Describing
 * the two methods used instead costs a dozen lines and removes both.
 *
 * A real `WorkOS` instance satisfies this: `intent` is widened from the SDK's
 * `GeneratePortalLinkIntent` enum to `string`, and TypeScript compares method
 * parameters bivariantly, so the narrower enum still assigns. What this does
 * give up is the compiler catching a typo in {@link AUDIT_LOGS_PORTAL_INTENT} —
 * covered by the test that asserts the intent this route sends.
 */
export interface WorkOSAuditClient {
  auditLogs: {
    createEvent(organization: string, event: WorkOSAuditEvent, options?: unknown): Promise<unknown>;
  };
  portal: {
    generateLink(options: {
      intent: string;
      organization: string;
      returnUrl?: string;
      successUrl?: string;
    }): Promise<{ link: string }>;
  };
}

function loose(c: unknown): Context {
  return c as Context;
}

function flattenMetadata(metadata: Record<string, unknown>): Record<string, string | number | boolean> {
  const flat: Record<string, string | number | boolean> = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (value === undefined || value === null) continue;
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      flat[key] = value;
      continue;
    }
    try {
      flat[key] = JSON.stringify(value);
    } catch {
      // Drop unserializable metadata rather than the event.
    }
  }
  return flat;
}

export function toWorkOSEvent(event: AuditEventRow): WorkOSAuditEvent {
  return {
    action: event.action,
    occurredAt: event.occurredAt,
    actor: { type: event.actorType === 'agent' ? 'agent' : 'user', id: event.actorId },
    targets: event.targets.map(target => ({
      type: target.type,
      id: target.id,
      ...(target.name !== undefined ? { name: target.name } : {}),
    })),
    context: {
      location: event.context.location ?? UNKNOWN_LOCATION,
      ...(event.context.userAgent !== undefined ? { userAgent: event.context.userAgent } : {}),
    },
    metadata: flattenMetadata(event.metadata),
  };
}

/** Optional WorkOS mirror and Admin Portal route, independent of the auth adapter. */
export class WorkOSAuditIntegration implements FactoryIntegration {
  readonly id = 'workos';
  readonly #client: WorkOSAuditClient;
  readonly #returnUrl: string;

  constructor({ client, returnUrl }: { client: WorkOSAuditClient; returnUrl: string }) {
    this.#client = client;
    this.#returnUrl = returnUrl;
  }

  async audit({ event }: { event: AuditEventRow }): Promise<void> {
    try {
      await this.#client.auditLogs.createEvent(event.orgId, toWorkOSEvent(event));
    } catch (err) {
      console.warn('[Audit] Failed to forward audit event to WorkOS', {
        action: event.action,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  routes(ctx: IntegrationContext): ApiRoute[] {
    const { auth } = ctx;
    return [
      registerApiRoute('/web/audit/portal-link', {
        method: 'GET',
        handler: async cc => {
          const c = loose(cc);
          await auth.ensureUser(c);
          const tenant = auth.tenant(c);
          if (!tenant) return c.json({ error: 'unauthorized' }, 401);
          if (!tenant.orgId) {
            return c.json(
              { error: 'organization_required', message: 'The audit trail requires a WorkOS organization.' },
              403,
            );
          }

          try {
            const { link } = await this.#client.portal.generateLink({
              organization: tenant.orgId,
              intent: AUDIT_LOGS_PORTAL_INTENT,
              returnUrl: this.#returnUrl,
            });
            return c.json({ url: link });
          } catch (err) {
            console.warn('[Audit] Failed to generate WorkOS Admin Portal link', {
              error: err instanceof Error ? err.message : String(err),
            });
            return c.json({ error: 'portal_link_failed' }, 502);
          }
        },
      }),
    ];
  }

  diagnostics(): Record<string, unknown> {
    return { configured: true };
  }
}
