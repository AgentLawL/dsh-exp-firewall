import { strict as assert } from 'node:assert'
import { createRequire } from 'node:module'
import { readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const artifact = resolve(process.argv[2] ?? resolve(root, 'lib/client.js'))
const code = await readFile(artifact, 'utf8')
let handoff
const window = {
  __ModuleLoader__: {
    load(value) {
      handoff = value
    },
  },
}

Function('window', code)(window)
assert.equal(handoff?.id, 'exp-firewall')
assert.equal(typeof handoff?.factory, 'function')

const require = createRequire(import.meta.url)
const exports = handoff.factory((specifier) => require(specifier))
assert.equal(exports.name, 'exp-firewall-client')
assert.deepEqual(exports.inject, ['slots'])
assert.equal(typeof exports.apply, 'function')
assert.equal(typeof exports.FirewallDashboard, 'function')
process.stdout.write('client ModuleLoader handoff: ok\n')
