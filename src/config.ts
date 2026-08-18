import { FirewallError } from './types/errors.ts'

/** Deployment mode for decision mapping. */
export type DeploymentMode = 'observe' | 'warn' | 'enforce'

/** Fully validated Exp Firewall configuration. */
export interface Config {
  mode: DeploymentMode
  dataDir: string
  minIndependentSupporters: number
  observationTtlMs: number
  verificationLeaseTtlMs: number
  storeBusyDeadlineMs: number
  enforceStoreFailure: 'allow' | 'deny'
  commandTools: string[]
  readTools: string[]
  policies: {
    command: { enforce: boolean }
    'file-read': { enforce: boolean }
  }
  dashboard: {
    enabled: boolean
    host: string
    pollIntervalMs: number
  }
  redaction: {
    maxPreviewChars: number
  }
}

/** Optional plugin-loader input resolved exactly once. */
export interface ConfigInput {
  mode?: DeploymentMode
  dataDir?: string
  minIndependentSupporters?: number
  observationTtlMs?: number
  verificationLeaseTtlMs?: number
  storeBusyDeadlineMs?: number
  enforceStoreFailure?: 'allow' | 'deny'
  commandTools?: string[]
  readTools?: string[]
  policies?: {
    command?: { enforce?: boolean }
    'file-read'?: { enforce?: boolean }
  }
  dashboard?: {
    enabled?: boolean
    host?: string
    pollIntervalMs?: number
  }
  redaction?: {
    maxPreviewChars?: number
  }
}

/** Normative configuration defaults. */
export const DEFAULT_CONFIG: Readonly<Config> = Object.freeze({
  mode: 'warn',
  dataDir: '.dsh/exp-firewall',
  minIndependentSupporters: 2,
  observationTtlMs: 300_000,
  verificationLeaseTtlMs: 60_000,
  storeBusyDeadlineMs: 2_000,
  enforceStoreFailure: 'allow',
  commandTools: Object.freeze(['bash', 'pwsh']) as unknown as string[],
  readTools: Object.freeze(['read']) as unknown as string[],
  policies: Object.freeze({
    command: Object.freeze({ enforce: true }),
    'file-read': Object.freeze({ enforce: true }),
  }),
  dashboard: Object.freeze({ enabled: true, host: '127.0.0.1', pollIntervalMs: 1_000 }),
  redaction: Object.freeze({ maxPreviewChars: 160 }),
})

function invalidConfig(message: string): never {
  throw new FirewallError('INVALID_CONFIG', message)
}

function requirePositiveSafeInteger(name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    invalidConfig(`${name} must be a positive safe integer.`)
  }
}

function validateToolList(name: string, tools: readonly string[]): void {
  const seen = new Set<string>()
  for (const tool of tools) {
    if (typeof tool !== 'string' || tool.trim().length === 0) {
      invalidConfig(`${name} must contain only non-empty tool names.`)
    }
    if (seen.has(tool)) {
      invalidConfig(`${name} must not contain duplicate tool names.`)
    }
    seen.add(tool)
  }
}

/**
 * Resolve defaults and validate all self-contained configuration.
 * @param input - Optional loader configuration.
 * @returns Fully populated configuration with owned mutable arrays.
 */
export function resolveConfig(input: ConfigInput = {}): Config {
  const config: Config = {
    mode: input.mode ?? DEFAULT_CONFIG.mode,
    dataDir: input.dataDir ?? DEFAULT_CONFIG.dataDir,
    minIndependentSupporters: input.minIndependentSupporters ?? DEFAULT_CONFIG.minIndependentSupporters,
    observationTtlMs: input.observationTtlMs ?? DEFAULT_CONFIG.observationTtlMs,
    verificationLeaseTtlMs: input.verificationLeaseTtlMs ?? DEFAULT_CONFIG.verificationLeaseTtlMs,
    storeBusyDeadlineMs: input.storeBusyDeadlineMs ?? DEFAULT_CONFIG.storeBusyDeadlineMs,
    enforceStoreFailure: input.enforceStoreFailure ?? DEFAULT_CONFIG.enforceStoreFailure,
    commandTools: [...(input.commandTools ?? DEFAULT_CONFIG.commandTools)],
    readTools: [...(input.readTools ?? DEFAULT_CONFIG.readTools)],
    policies: {
      command: { enforce: input.policies?.command?.enforce ?? DEFAULT_CONFIG.policies.command.enforce },
      'file-read': {
        enforce: input.policies?.['file-read']?.enforce ?? DEFAULT_CONFIG.policies['file-read'].enforce,
      },
    },
    dashboard: {
      enabled: input.dashboard?.enabled ?? DEFAULT_CONFIG.dashboard.enabled,
      host: input.dashboard?.host ?? DEFAULT_CONFIG.dashboard.host,
      pollIntervalMs: input.dashboard?.pollIntervalMs ?? DEFAULT_CONFIG.dashboard.pollIntervalMs,
    },
    redaction: {
      maxPreviewChars: input.redaction?.maxPreviewChars ?? DEFAULT_CONFIG.redaction.maxPreviewChars,
    },
  }

  if (!['observe', 'warn', 'enforce'].includes(config.mode)) {
    invalidConfig('mode must be observe, warn, or enforce.')
  }
  if (config.dataDir.trim().length === 0) {
    invalidConfig('dataDir must be a non-empty path.')
  }
  if (!['allow', 'deny'].includes(config.enforceStoreFailure)) {
    invalidConfig('enforceStoreFailure must be allow or deny.')
  }
  requirePositiveSafeInteger('observationTtlMs', config.observationTtlMs)
  requirePositiveSafeInteger('verificationLeaseTtlMs', config.verificationLeaseTtlMs)
  requirePositiveSafeInteger('storeBusyDeadlineMs', config.storeBusyDeadlineMs)
  requirePositiveSafeInteger('dashboard.pollIntervalMs', config.dashboard.pollIntervalMs)
  if (!Number.isSafeInteger(config.minIndependentSupporters) || config.minIndependentSupporters < 2) {
    invalidConfig('minIndependentSupporters must be a safe integer of at least two.')
  }
  if (
    !Number.isSafeInteger(config.redaction.maxPreviewChars) ||
    config.redaction.maxPreviewChars < 40 ||
    config.redaction.maxPreviewChars > 1_000
  ) {
    invalidConfig('redaction.maxPreviewChars must be a safe integer between 40 and 1000.')
  }
  validateToolList('commandTools', config.commandTools)
  validateToolList('readTools', config.readTools)
  const commandTools = new Set(config.commandTools)
  if (config.readTools.some((tool) => commandTools.has(tool))) {
    invalidConfig('commandTools and readTools must not overlap.')
  }
  if (config.dashboard.host.trim().length === 0) {
    invalidConfig('dashboard.host must be a non-empty hostname or address.')
  }

  return config
}
