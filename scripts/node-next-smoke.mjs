import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const root = resolve(import.meta.dirname, '..')
const packageJson = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8'))

for (const key of ['.', './client', './types', './pure']) {
  const target = packageJson.exports[key]
  const exportTarget = typeof target === 'string' ? target : target.default
  await import(pathToFileURL(resolve(root, exportTarget)).href)
}
