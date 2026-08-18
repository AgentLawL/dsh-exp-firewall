import { execFile } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, describe, expect, it } from 'vitest'

import { resolveConfig } from '../src/config.ts'
import { SqliteExperienceFirewallStore } from '../src/store-service.ts'
import { claimId, observation } from './helpers.ts'

const execute = promisify(execFile)
let dataDir: string | undefined

afterEach(async () => {
  if (dataDir !== undefined) await rm(dataDir, { recursive: true, force: true })
  dataDir = undefined
})

async function cli(...args: string[]) {
  return execute(process.execPath, ['src/cli.ts', ...args], {
    cwd: process.cwd(),
    env: { ...process.env, EXP_FIREWALL_DATA_DIR: dataDir },
  })
}

describe('read-only CLI process', () => {
  it('supports help, status, claims, claim, events, filters, and stable errors', async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'exp-firewall-cli-'))
    const store = new SqliteExperienceFirewallStore(resolveConfig({ dataDir }))
    const seen = observation({
      id: 'cli-observation', principal: 'cli-agent', at: '2026-08-18T00:00:00.000Z',
      outcome: 'failure', failureCode: 'FS_NOT_FOUND',
    })
    await store.record({ operationId: seen.operationId, observation: seen, newClaimId: claimId('claim-cli'), now: seen.observedAt })
    await store.shutdown()

    expect((await cli('--help')).stdout).toContain('exp-firewall status')
    expect(JSON.parse((await cli('status', '--scope', '/workspace')).stdout)).toMatchObject({ suspectedClaims: 1 })
    expect(JSON.parse((await cli('claims', '--status', 'suspected', '--limit', '1')).stdout)).toMatchObject({
      items: [{ id: 'claim-cli', preview: 'read /target' }],
    })
    expect(JSON.parse((await cli('claim', 'claim-cli')).stdout)).toMatchObject({
      id: 'claim-cli', observations: [{ failureCode: 'FS_NOT_FOUND' }],
    })
    expect(JSON.parse((await cli('events', '--claim', 'claim-cli')).stdout)).toMatchObject({
      items: expect.arrayContaining([expect.objectContaining({ claimId: 'claim-cli' })]),
    })
    await expect(cli('claim', 'missing')).rejects.toMatchObject({
      code: 2,
      stderr: expect.stringContaining('CLAIM_NOT_FOUND'),
    })
    await expect(cli('claims', '--status', 'not-a-status')).rejects.toMatchObject({
      code: 2,
      stderr: expect.stringContaining('INVALID_ACTION'),
    })
  })
})
