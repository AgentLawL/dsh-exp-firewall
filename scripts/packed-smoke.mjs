import { strict as assert } from 'node:assert'
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const suppliedArtifact = process.argv.slice(2).find((argument) => argument !== '--')
const artifact = resolve(suppliedArtifact ?? join(root, 'artifacts', 'exp-firewall-0.1.0.tgz'))
const fixture = await mkdtemp(join(tmpdir(), 'exp-firewall-packed-'))
const packageDir = join(fixture, 'node_modules', 'exp-firewall')

try {
  await mkdir(packageDir, { recursive: true })
  const unpack = spawnSync('tar', ['-xzf', artifact, '--strip-components=1', '-C', packageDir], {
    encoding: 'utf8',
  })
  assert.equal(unpack.status, 0, unpack.stderr || unpack.error?.message)

  await symlink(join(root, 'node_modules'), join(packageDir, 'node_modules'), 'dir')
  const smokeFile = join(fixture, 'smoke.mjs')
  await writeFile(smokeFile, [
    "import * as main from 'exp-firewall'",
    "import * as dashboard from 'exp-firewall/dashboard'",
    "import * as service from 'exp-firewall/service'",
    "import { pureApiVersion } from 'exp-firewall/pure'",
    "import * as client from 'exp-firewall/client'",
    "if (typeof main.apply !== 'function' || main.name !== 'exp-firewall') throw new Error('invalid main export')",
    "if (typeof service.apply !== 'function' || typeof dashboard.apply !== 'function') throw new Error('invalid plugin export')",
    "if (pureApiVersion !== 1 || typeof client.OverviewPoller !== 'function') throw new Error('invalid subpath export')",
    "process.stdout.write('packed exports: ok\\n')",
    '',
  ].join('\n'))
  const imported = spawnSync(process.execPath, [smokeFile], { cwd: fixture, encoding: 'utf8' })
  assert.equal(imported.status, 0, imported.stderr)
  assert.equal(imported.stdout, 'packed exports: ok\n')
  process.stdout.write(imported.stdout)

  const manifest = JSON.parse(await readFile(join(packageDir, 'package.json'), 'utf8'))
  assert.equal(manifest.dsh.bundle.patch, './cordis.patch.yml')
  for (const relative of [
    'assets/evidence-recovery.gif',
    'cordis.patch.yml',
    'README.md',
    'README.zh.md',
    'lib/index.js',
    'lib/types/index.d.ts',
  ]) {
    await readFile(join(packageDir, relative))
  }
  process.stdout.write('packed contents: ok\n')
} finally {
  await rm(fixture, { recursive: true, force: true })
}
