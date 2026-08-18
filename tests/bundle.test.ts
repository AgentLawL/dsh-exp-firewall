import { composeEntries, loadOverlayPatches } from '@deepseek-ai/dsh-app-boot'
import { applyEntryPatches } from '@deepseek-ai/cordis-plugin-include'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const patchFile = fileURLToPath(new URL('../cordis.patch.yml', import.meta.url))

describe('DSH Bundle composition', () => {
  it('mounts the Provider before the Consumer and keeps Dashboard disabled', () => {
    const warnings: string[] = []
    const entries = composeEntries(
      [loadOverlayPatches('exp-firewall-test', patchFile)],
      (warning) => warnings.push(warning),
    )

    expect(warnings).toEqual([])
    expect(entries.map((entry) => entry.id)).toEqual([
      'exp-firewall-service',
      'exp-firewall',
      'exp-firewall-dashboard',
    ])
    expect(entries[0]).toMatchObject({ name: 'exp-firewall/service' })
    expect(entries[1]).toMatchObject({ name: 'exp-firewall', inject: ['expFirewall'] })
    expect(entries[2]).toMatchObject({
      name: 'exp-firewall/dashboard',
      disabled: true,
      inject: ['expFirewall', 'webServer'],
    })
  })

  it('lets a Profile override deployment config and enable Dashboard', () => {
    const base = composeEntries([loadOverlayPatches('exp-firewall-test', patchFile)])
    const warnings: string[] = []
    const configured = applyEntryPatches(base, [
      {
        id: 'exp-firewall-service',
        config: { mode: 'enforce', dataDir: '/profile/firewall' },
      },
      {
        id: 'exp-firewall',
        config: { mode: 'enforce', commandTools: ['shell'] },
      },
      {
        id: 'exp-firewall-dashboard',
        disabled: false,
        config: { dashboard: { enabled: true, host: '127.0.0.1' } },
      },
    ], (message) => warnings.push(message))

    expect(warnings).toEqual([])
    expect(configured).toMatchObject([
      { config: { mode: 'enforce', dataDir: '/profile/firewall' } },
      { config: { mode: 'enforce', commandTools: ['shell'] } },
      { disabled: false, config: { dashboard: { enabled: true, host: '127.0.0.1' } } },
    ])
  })
})
