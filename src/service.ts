import { Service, type Context } from '@deepseek-ai/cordis'

import { resolveConfig, type ConfigInput } from './config.ts'
import { SqliteExperienceFirewallStore } from './store-service.ts'
import type {
  DecisionRequest,
  ExperienceFirewallService,
  FirewallChangeNotification,
  FirewallEvent,
  ExperienceFirewallRuntimeService,
  InvalidateClaimsRequest,
  InvalidateClaimsResult,
  RecordObservationRequest,
  RecordResult,
  RecordWarningRequest,
  ReleaseLeaseCommand,
  SettleLeaseRequest,
  SettleResult,
} from './store.ts'
import type {
  ClaimDetail,
  ClaimFilter,
  ClaimId,
  ClaimView,
  Decision,
  EventFilter,
  FirewallSummary,
  Page,
  SummaryFilter,
} from './types/domain.ts'

/** Isolated, closeable notification fan-out for optional read-only surfaces. */
export class FirewallNotificationBus {
  readonly #listeners = new Set<(notification: FirewallChangeNotification) => void>()
  readonly #onError: (error: unknown) => void
  #accepting = true

  constructor(onError: (error: unknown) => void = () => undefined) {
    this.#onError = onError
  }

  subscribe(listener: (notification: FirewallChangeNotification) => void): () => void {
    if (!this.#accepting) return () => undefined
    this.#listeners.add(listener)
    return () => {
      this.#listeners.delete(listener)
    }
  }

  publish(notification: FirewallChangeNotification): void {
    if (!this.#accepting) return
    for (const listener of [...this.#listeners]) {
      try {
        const returned = listener(notification) as unknown
        if (returned !== null && typeof returned === 'object' && 'then' in returned) {
          void Promise.resolve(returned).catch(this.#onError)
        }
      } catch (error) {
        this.#onError(error)
      }
    }
  }

  close(): void {
    this.#accepting = false
    this.#listeners.clear()
  }
}

/** Service Provider plugin entry name. */
export const servicePluginName = 'exp-firewall-service'

declare module '@deepseek-ai/cordis' {
  interface Context {
    expFirewall: ExperienceFirewallRuntimeService
  }
}

/** Cordis Service Provider delegating to the durable SQLite Store. */
export class ExperienceFirewallProvider extends Service implements ExperienceFirewallRuntimeService {
  /** Durable implementation delegated through the Cordis service proxy. */
  readonly store: SqliteExperienceFirewallStore
  /** Exception-isolated notifications consumed only by optional read surfaces. */
  readonly notifications: FirewallNotificationBus

  /**
   * Register `ctx.expFirewall` and open its durable Store.
   * @param ctx - Owning Cordis context.
   * @param config - Fully resolved configuration.
   */
  constructor(ctx: Context, config: ReturnType<typeof resolveConfig>) {
    super(ctx, 'expFirewall')
    this.store = new SqliteExperienceFirewallStore(config)
    this.notifications = new FirewallNotificationBus(() => {
      ctx.logger('exp-firewall').warn('read-surface subscriber failed')
    })
  }

  async decide(request: DecisionRequest): Promise<Decision> {
    const result = await this.store.decide(request)
    this.notifications.publish({ kind: 'decision', operationId: request.operationId })
    return result
  }

  async record(request: RecordObservationRequest): Promise<RecordResult> {
    const result = await this.store.record(request)
    this.notifications.publish({ kind: 'observation', operationId: request.operationId })
    return result
  }

  async recordWarning(request: RecordWarningRequest): Promise<{ recorded: true }> {
    const result = await this.store.recordWarning(request)
    this.notifications.publish({ kind: 'warning', operationId: request.operationId })
    return result
  }

  async settleLease(request: SettleLeaseRequest): Promise<SettleResult> {
    const result = await this.store.settleLease(request)
    this.notifications.publish({ kind: 'lease-settlement', operationId: request.operationId })
    return result
  }

  async invalidateClaims(request: InvalidateClaimsRequest): Promise<InvalidateClaimsResult> {
    const result = await this.store.invalidateClaims(request)
    this.notifications.publish({ kind: 'evidence-invalidation', operationId: request.operationId })
    return result
  }

  async releaseLease(request: ReleaseLeaseCommand) {
    const result = await this.store.releaseLease(request)
    this.notifications.publish({ kind: 'lease-release', operationId: request.operationId })
    return result
  }

  subscribe(listener: (notification: FirewallChangeNotification) => void): () => void {
    return this.notifications.subscribe(listener)
  }

  closeSubscriptions(): void {
    this.notifications.close()
  }

  async summary(filter?: SummaryFilter): Promise<FirewallSummary> {
    return this.store.summary(filter)
  }

  async listClaims(filter?: ClaimFilter): Promise<Page<ClaimView>> {
    return this.store.listClaims(filter)
  }

  async getClaim(id: ClaimId, signal?: AbortSignal): Promise<ClaimDetail | undefined> {
    return this.store.getClaim(id, signal)
  }

  async listEvents(filter?: EventFilter): Promise<Page<FirewallEvent>> {
    return this.store.listEvents(filter)
  }

  async shutdown(): Promise<void> {
    this.notifications.close()
    return this.store.shutdown()
  }
}

/**
 * Load the durable Service Provider entry.
 * @param _context - Cordis-compatible host context, reserved for the Provider.
 * @param _config - Unresolved plugin configuration.
 */
export function apply(context: Context, input: ConfigInput = {}): void {
  const provider = new ExperienceFirewallProvider(context, resolveConfig(input))
  context.effect(() => () => provider.shutdown(), 'exp-firewall Store shutdown')
}
