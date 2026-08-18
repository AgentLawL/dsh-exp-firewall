import { createHash } from 'node:crypto'

import { FirewallError } from './types/errors.ts'
import type { Fingerprint } from './types/domain.ts'

/** JSON values accepted by deterministic serialization. */
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue | undefined }

/** Canonical command action used only for exact identity. */
export interface CommandAction {
  kind: 'command'
  tool: string
  cwd: string
  command: string
}

/** Canonical file-read action used only for exact identity. */
export interface FileReadAction {
  kind: 'file-read'
  tool: string
  cwd: string
  path: string
}

/** Supported canonical action. */
export type CanonicalAction = CommandAction | FileReadAction

/** Input needed to canonicalize a command tool call. */
export interface CommandActionInput {
  tool: string
  command: unknown
  workdir?: unknown
  sessionCwd?: string
}

/** Input needed to canonicalize a file-read tool call. */
export interface FileReadActionInput {
  tool: string
  path: unknown
  workdir?: unknown
  sessionCwd?: string
  providerDisplayPath?: string
}

function normalizeJson(value: unknown, ancestors: Set<object>): JsonValue | undefined {
  if (value === undefined) return undefined
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new FirewallError('INVALID_ACTION', 'Stable JSON rejects non-finite numbers.')
    return value
  }
  if (typeof value !== 'object') {
    throw new FirewallError('INVALID_ACTION', 'Stable JSON accepts only JSON values.')
  }
  if (ancestors.has(value)) {
    throw new FirewallError('INVALID_ACTION', 'Stable JSON rejects cyclic values.')
  }

  ancestors.add(value)
  try {
    if (Array.isArray(value)) {
      return value.map((entry) => {
        const normalized = normalizeJson(entry, ancestors)
        if (normalized === undefined) {
          throw new FirewallError('INVALID_ACTION', 'Stable JSON rejects undefined array entries.')
        }
        return normalized
      })
    }

    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) {
      throw new FirewallError('INVALID_ACTION', 'Stable JSON rejects non-plain objects.')
    }
    const result: Record<string, JsonValue> = {}
    for (const key of Object.keys(value).sort()) {
      const normalized = normalizeJson((value as Record<string, unknown>)[key], ancestors)
      if (normalized !== undefined) result[key] = normalized
    }
    return result
  } finally {
    ancestors.delete(value)
  }
}

/**
 * Serialize JSON with object keys sorted lexicographically at every depth.
 * @param value - JSON-compatible input.
 * @returns Deterministic JSON text.
 */
export function stableJson(value: unknown): string {
  const normalized = normalizeJson(value, new Set())
  if (normalized === undefined) {
    throw new FirewallError('INVALID_ACTION', 'Stable JSON requires a defined root value.')
  }
  return JSON.stringify(normalized)
}

function requireTool(tool: string): string {
  if (typeof tool !== 'string' || tool.length === 0) {
    throw new FirewallError('INVALID_ACTION', 'A supported action requires a non-empty tool name.')
  }
  return tool
}

function effectiveCwd(workdir: unknown, sessionCwd: string | undefined): string {
  if (workdir !== undefined && typeof workdir !== 'string') {
    throw new FirewallError('INVALID_ACTION', 'Tool workdir must be a string when provided.')
  }
  return workdir ?? sessionCwd ?? ''
}

/**
 * Canonicalize a command without changing internal whitespace.
 * @param input - Tool name, command, and cwd sources.
 * @returns Exact command action identity fields.
 */
export function canonicalizeCommandAction(input: CommandActionInput): CommandAction {
  if (typeof input.command !== 'string') {
    throw new FirewallError('INVALID_ACTION', 'Command tool arguments require a string command.')
  }
  const command = input.command.trim()
  if (command.length === 0) {
    throw new FirewallError('INVALID_ACTION', 'Command must not be empty after trimming.')
  }
  return {
    kind: 'command',
    tool: requireTool(input.tool),
    cwd: effectiveCwd(input.workdir, input.sessionCwd),
    command,
  }
}

/** Remove model-supplied C0 and C1 control characters. */
export function removePathControlCharacters(path: string): string {
  return path.replace(/[\u0000-\u001f\u007f-\u009f]/g, '')
}

/**
 * Canonicalize a file read without independently resolving symlinks.
 * @param input - Tool name, path sources, and optional Provider display path.
 * @returns Exact file-read action identity fields.
 */
export function canonicalizeFileReadAction(input: FileReadActionInput): FileReadAction {
  if (typeof input.path !== 'string') {
    throw new FirewallError('INVALID_ACTION', 'File-read arguments require a string path.')
  }
  const modelPath = removePathControlCharacters(input.path)
  const providerPath =
    input.providerDisplayPath === undefined ? undefined : removePathControlCharacters(input.providerDisplayPath)
  const path = providerPath && providerPath.length > 0 ? providerPath : modelPath
  if (path.length === 0) {
    throw new FirewallError('INVALID_ACTION', 'File-read path must not be empty.')
  }
  return {
    kind: 'file-read',
    tool: requireTool(input.tool),
    cwd: effectiveCwd(input.workdir, input.sessionCwd),
    path,
  }
}

/**
 * Compute the full lowercase SHA-256 action fingerprint.
 * @param action - Canonical supported action.
 * @returns Branded exact-match digest.
 */
export function fingerprintAction(action: CanonicalAction): Fingerprint {
  return createHash('sha256').update(stableJson(action), 'utf8').digest('hex') as Fingerprint
}
