#!/usr/bin/env node
import { pathToFileURL } from 'node:url'

import { resolveConfig } from './config.ts'
import { SqliteExperienceFirewallStore } from './store-service.ts'
import type { ClaimStatus } from './types/domain.ts'
import { FirewallError } from './types/errors.ts'

/** Injectable CLI streams and environment used by process tests. */
export interface CliIo {
  stdout(text: string): void
  stderr(text: string): void
}

const HELP = `Usage:
  exp-firewall status [--scope <scope>]
  exp-firewall claims [--status <status>] [--scope <scope>] [--cursor <cursor>] [--limit <n>]
  exp-firewall claim <id>
  exp-firewall events [--claim <id>] [--cursor <cursor>] [--limit <n>]
`
const CLAIM_STATUSES = new Set<ClaimStatus>([
  'suspected', 'corroborated', 'stale', 'verifying', 'contradicted', 'resolved', 'superseded',
])

function parseFlags(args: readonly string[], allowed: readonly string[]): Record<string, string> {
  const result: Record<string, string> = {}
  const names = new Set(allowed)
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index]
    const value = args[index + 1]
    if (flag === undefined || !flag.startsWith('--') || !names.has(flag.slice(2)) || value === undefined) {
      throw new FirewallError('INVALID_ACTION', 'Invalid CLI arguments; run exp-firewall --help for supported read-only commands.')
    }
    if (result[flag.slice(2)] !== undefined) throw new FirewallError('INVALID_ACTION', `CLI flag ${flag} may appear once.`)
    result[flag.slice(2)] = value
  }
  return result
}

function limit(value: string | undefined): number | undefined {
  if (value === undefined) return undefined
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 200) {
    throw new FirewallError('INVALID_ACTION', 'CLI limit must be an integer from 1 to 200.')
  }
  return parsed
}

/** Run one read-only CLI invocation and return its process exit code. */
export async function runCli(
  args: readonly string[],
  io: CliIo = { stdout: (text) => process.stdout.write(text), stderr: (text) => process.stderr.write(text) },
  dataDir = process.env.EXP_FIREWALL_DATA_DIR,
): Promise<number> {
  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    io.stdout(HELP)
    return 0
  }
  const config = resolveConfig({ ...(dataDir === undefined ? {} : { dataDir }) })
  let store: SqliteExperienceFirewallStore | undefined
  try {
    store = new SqliteExperienceFirewallStore(config)
    let value: unknown
    switch (args[0]) {
      case 'status': {
        const flags = parseFlags(args.slice(1), ['scope'])
        value = await store.summary({ ...(flags.scope === undefined ? {} : { scope: flags.scope }) })
        break
      }
      case 'claims': {
        const flags = parseFlags(args.slice(1), ['status', 'scope', 'cursor', 'limit'])
        if (flags.status !== undefined && !CLAIM_STATUSES.has(flags.status as ClaimStatus)) {
          throw new FirewallError('INVALID_ACTION', 'CLI status is not a known Claim status.')
        }
        const parsedLimit = limit(flags.limit)
        value = await store.listClaims({
          ...(flags.status === undefined ? {} : { status: flags.status as ClaimStatus }),
          ...(flags.scope === undefined ? {} : { scope: flags.scope }),
          ...(flags.cursor === undefined ? {} : { cursor: flags.cursor }),
          ...(parsedLimit === undefined ? {} : { limit: parsedLimit }),
        })
        break
      }
      case 'claim': {
        if (args.length !== 2) throw new FirewallError('INVALID_ACTION', 'claim requires exactly one Claim ID.')
        value = await store.getClaim(args[1] as never)
        if (value === undefined) throw new FirewallError('CLAIM_NOT_FOUND', 'The requested Claim does not exist.')
        break
      }
      case 'events': {
        const flags = parseFlags(args.slice(1), ['claim', 'cursor', 'limit'])
        const parsedLimit = limit(flags.limit)
        value = await store.listEvents({
          ...(flags.claim === undefined ? {} : { claimId: flags.claim as never }),
          ...(flags.cursor === undefined ? {} : { cursor: flags.cursor }),
          ...(parsedLimit === undefined ? {} : { limit: parsedLimit }),
        })
        break
      }
      default:
        throw new FirewallError('INVALID_ACTION', 'Unknown CLI command; run exp-firewall --help.')
    }
    io.stdout(`${JSON.stringify(value, null, 2)}\n`)
    return 0
  } catch (error) {
    const code = error instanceof FirewallError ? error.code : 'STORE_CORRUPT'
    const message = error instanceof FirewallError ? error.message : 'The Exp Firewall Store could not be read.'
    io.stderr(`${JSON.stringify({ code, message })}\n`)
    return code === 'CLAIM_NOT_FOUND' || code === 'INVALID_ACTION' ? 2 : 1
  } finally {
    await store?.shutdown()
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await runCli(process.argv.slice(2))
}
