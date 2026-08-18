/**
 * Host-side Exp Firewall plugin entry.
 *
 * The complete runtime composition is introduced after the pure and durable
 * service layers. This entry remains independently loadable while those roles
 * are assembled by the bundle patch.
 *
 * @module exp-firewall
 */

export { apply, consumerPluginName, ExperienceFirewallConsumer, inject } from './consumer.ts'
export { DEFAULT_CONFIG, resolveConfig } from './config.ts'
export type { Config, ConfigInput, DeploymentMode } from './config.ts'
export { dashboardPluginName } from './web-api.ts'
export { servicePluginName } from './service.ts'
export { SqliteExperienceFirewallStore } from './store-service.ts'
export * from './session-events.ts'
export * from './types/index.ts'
export type { ExperienceFirewallService, ExperienceFirewallStore } from './store.ts'

/** Host plugin name. */
export const name = 'exp-firewall'
