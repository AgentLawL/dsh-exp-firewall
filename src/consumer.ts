import type { Context } from '@deepseek-ai/cordis'
import type { FsObservation, FsTarget } from '@deepseek-ai/dsh-fs'
import type {
  PostToolDecision,
  PreToolDecision,
  ToolExecution,
  ToolExecutionResult,
} from '@deepseek-ai/dsh-tools'

import { resolveConfig, type Config } from './config.ts'
import { canonicalizeCommandAction, canonicalizeFileReadAction, fingerprintAction } from './fingerprint.ts'
import { createPreview } from './redaction.ts'
import { appendFirewallSessionEvent, projectFirewallDecisionNotice } from './session-events.ts'
import type { EvidenceWitness, Fingerprint, LeaseId, PrincipalId, VerificationLease } from './types/domain.ts'
import {
  createClaimId,
  createLeaseId,
  createObservationId,
  createOperationId,
  derivePrincipalId,
} from './types/ids.ts'
import { toUtcIso } from './types/time.ts'
import { evidenceEpoch } from './evidence.ts'

/** Tool-policy Consumer plugin entry name. */
export const consumerPluginName = 'exp-firewall'
/** Service injection required before policy listeners register. */
export const inject = ['expFirewall']

interface PendingCall {
  actionKind: 'command' | 'file-read'
  fingerprint: Fingerprint
  preview: string
  scope: string
  principalId: PrincipalId
  evidence: EvidenceWitness[]
  decisionOperationId: ReturnType<typeof createOperationId>
  decision?: Awaited<ReturnType<Context['expFirewall']['decide']>>
  modelPathKey?: string
  toolCallId: string
}

function sessionFor(exec: ToolExecution): import('./session-events.ts').FirewallSessionAppender {
  return exec.agent!.session as unknown as import('./session-events.ts').FirewallSessionAppender
}

interface RecordValue {
  exitCode?: unknown
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}

function sessionCwd(exec: ToolExecution): string {
  return exec.agent?.session.header.cwd ?? ''
}

function principal(exec: ToolExecution): PrincipalId | undefined {
  const session = exec.agent?.session
  if (session === undefined) return undefined
  return derivePrincipalId(exec.agent?.id, session.id)
}

function scope(exec: ToolExecution): string {
  return sessionCwd(exec)
}

function decisionReason(decision: PendingCall['decision'], operationId: PendingCall['decisionOperationId']): string {
  if (decision === undefined) return 'unavailable'
  return projectFirewallDecisionNotice(
    {
      operationId,
      ...('claimId' in decision && decision.claimId !== undefined ? { claimId: decision.claimId } : {}),
      decision: decision.kind,
      reason: decision.reason,
    },
    240,
  ) ?? '[exp-firewall] allowed'
}

function classifyResult(
  actionKind: PendingCall['actionKind'],
  result: Readonly<ToolExecutionResult>,
): { outcome: 'success' | 'failure'; failureCode?: string } {
  if (actionKind === 'command') {
    if (!result.isError) {
      const exitCode = (objectValue(result.value) as RecordValue | undefined)?.exitCode
      if (typeof exitCode === 'number' && Number.isInteger(exitCode)) {
        return exitCode === 0 ? { outcome: 'success' } : { outcome: 'failure', failureCode: `EXIT_${exitCode}` }
      }
      return { outcome: 'failure' }
    }
    return { outcome: 'failure' }
  }
  if (!result.isError) return { outcome: 'success' }
  return result.error.info?.code === 'FS_NOT_FOUND'
    ? { outcome: 'failure', failureCode: 'FS_NOT_FOUND' }
    : { outcome: 'failure' }
}

class EvidenceCache {
  readonly #latest = new Map<string, EvidenceWitness>()
  readonly #aliases = new Map<string, string>()

  modelKey(cwd: string, path: string): string {
    return `${cwd}\u0000${path}`
  }

  evidenceFor(modelKey: string): EvidenceWitness[] {
    const displayPath = this.#aliases.get(modelKey)
    if (displayPath === undefined) return []
    const witness = this.#latest.get(displayPath)
    return witness === undefined ? [] : [{ ...witness }]
  }

  displayPathFor(modelKey: string): string | undefined {
    return this.#aliases.get(modelKey)
  }

  observe(target: FsTarget, observation: FsObservation, modelKey?: string): EvidenceWitness {
    const witness: EvidenceWitness = observation.kind === 'absent'
      ? { kind: 'file-state', key: target.displayPath, state: 'absent' }
      : { kind: 'file-state', key: target.displayPath, state: 'present', version: observation.version }
    this.#latest.set(target.displayPath, witness)
    if (modelKey !== undefined) this.#aliases.set(modelKey, target.displayPath)
    return witness
  }

  clear(): void {
    this.#latest.clear()
    this.#aliases.clear()
  }
}

class InvalidationQueue {
  #tail: Promise<void> = Promise.resolve()
  #accepting = true
  readonly #onError: (error: unknown) => void

  constructor(onError: (error: unknown) => void) {
    this.#onError = onError
  }

  enqueue(task: () => Promise<unknown>): void {
    if (!this.#accepting) return
    this.#tail = this.#tail.then(task).then(
      () => undefined,
      (error) => this.#onError(error),
    )
  }

  async stopAndDrain(): Promise<void> {
    this.#accepting = false
    await this.#tail
  }
}

/** Runtime Consumer owning pre/post correlation and the latest Evidence cache. */
export class ExperienceFirewallConsumer {
  readonly #ctx: Context
  readonly #config: Config
  readonly #cache = new EvidenceCache()
  readonly #invalidationQueue: InvalidationQueue
  readonly #pending = new WeakMap<object, PendingCall>()
  readonly #ownedLeases = new Map<LeaseId, PrincipalId>()
  #accepting = true
  #stopPromise?: Promise<void>

  /**
   * Register effects on the owning Cordis context.
   * @param ctx - Context carrying tools, fs events, and `expFirewall`.
   * @param config - Fully resolved plugin configuration.
   */
  constructor(ctx: Context, config: Config) {
    this.#ctx = ctx
    this.#config = config
    this.#invalidationQueue = new InvalidationQueue((error) => this.#diagnose('evidence invalidation failed', error))
  }

  #diagnose(message: string, error?: unknown): void {
    try {
      const code = objectValue(error)?.code
      const suffix = typeof code === 'string' ? ` (${code})` : ''
      this.#ctx.logger('exp-firewall').warn(`${message}${suffix}`)
    } catch {
      // Diagnostics must never change policy or tool execution.
    }
  }

  #prepare(exec: ToolExecution): PendingCall | undefined {
    const principalId = principal(exec)
    if (principalId === undefined) return undefined
    const args = objectValue(exec.arguments)
    if (args === undefined) return undefined
    const cwd = sessionCwd(exec)
    if (this.#config.commandTools.includes(exec.name)) {
      const action = canonicalizeCommandAction({
        tool: exec.name,
        command: args.command,
        workdir: args.workdir,
        sessionCwd: cwd,
      })
      return {
        actionKind: 'command',
        fingerprint: fingerprintAction(action),
        preview: createPreview(action.command, this.#config.redaction.maxPreviewChars),
        scope: scope(exec),
        principalId,
        evidence: [],
        decisionOperationId: createOperationId(),
        toolCallId: exec.callId,
      }
    }
    if (this.#config.readTools.includes(exec.name)) {
      const initialAction = canonicalizeFileReadAction({
        tool: exec.name,
        path: args.path,
        workdir: args.workdir,
        sessionCwd: cwd,
      })
      const modelPathKey = this.#cache.modelKey(initialAction.cwd, initialAction.path)
      const providerDisplayPath = this.#cache.displayPathFor(modelPathKey)
      const action = canonicalizeFileReadAction({
        tool: exec.name,
        path: args.path,
        workdir: args.workdir,
        sessionCwd: cwd,
        ...(providerDisplayPath === undefined ? {} : { providerDisplayPath }),
      })
      return {
        actionKind: 'file-read',
        fingerprint: fingerprintAction(action),
        preview: createPreview(action.path, this.#config.redaction.maxPreviewChars),
        scope: scope(exec),
        principalId,
        evidence: this.#cache.evidenceFor(modelPathKey),
        decisionOperationId: createOperationId(),
        modelPathKey,
        toolCallId: exec.callId,
      }
    }
    return undefined
  }

  async preExecute(exec: ToolExecution, next: () => Promise<PreToolDecision>): Promise<PreToolDecision> {
    if (!this.#accepting) return next()
    let pending: PendingCall | undefined
    try {
      pending = this.#prepare(exec)
    } catch {
      return { kind: 'deny', reason: '[exp-firewall] invalid configured tool arguments' }
    }
    if (pending === undefined) return next()
    this.#pending.set(exec, pending)
    const now = toUtcIso(Date.now())
    try {
      const candidateLease: Omit<VerificationLease, 'claimId'> = {
        id: createLeaseId(),
        ownerPrincipalId: pending.principalId,
        evidenceEpoch: evidenceEpoch(pending.evidence),
        expiresAt: toUtcIso(Date.parse(now) + this.#config.verificationLeaseTtlMs),
      }
      const decision = await this.#ctx.expFirewall.decide({
        operationId: pending.decisionOperationId,
        scope: pending.scope,
        actionKind: pending.actionKind,
        fingerprint: pending.fingerprint,
        principalId: pending.principalId,
        evidence: pending.evidence,
        now,
        candidateLease,
      })
      pending.decision = decision
      if (decision.kind === 'verify') {
        this.#ownedLeases.set(decision.leaseId, pending.principalId)
      }
      if (decision.kind !== 'allow') {
        appendFirewallSessionEvent(sessionFor(exec), 'exp-firewall/decision', {
          operationId: pending.decisionOperationId,
          ...('claimId' in decision && decision.claimId !== undefined ? { claimId: decision.claimId } : {}),
          decision: decision.kind,
          reason: decision.reason,
        })
      }
      if (decision.kind === 'deny' || decision.kind === 'wait') {
        this.#pending.delete(exec)
        return { kind: 'deny', reason: decisionReason(decision, pending.decisionOperationId) }
      }
    } catch (error) {
      this.#diagnose('pre-execution Store decision failed', error)
      if (this.#config.mode === 'enforce' && this.#config.enforceStoreFailure === 'deny') {
        this.#pending.delete(exec)
        return { kind: 'deny', reason: '[exp-firewall] policy store unavailable' }
      }
    }
    return next()
  }

  async postExecute(
    exec: ToolExecution,
    result: Readonly<ToolExecutionResult>,
    next: () => Promise<PostToolDecision>,
  ): Promise<PostToolDecision> {
    const delegated = await next()
    const pending = this.#pending.get(exec)
    if (pending === undefined) return delegated
    this.#pending.delete(exec)
    const classified = classifyResult(pending.actionKind, result)
    const now = toUtcIso(Date.now())
    const observation = {
      id: createObservationId(),
      operationId: createOperationId(),
      sessionId: String(exec.agent!.session.id),
      principalId: pending.principalId,
      toolCallId: pending.toolCallId,
      scope: pending.scope,
      actionKind: pending.actionKind,
      fingerprint: pending.fingerprint,
      preview: pending.preview,
      outcome: classified.outcome,
      ...(classified.failureCode === undefined ? {} : { failureCode: classified.failureCode }),
      evidenceEpoch: evidenceEpoch(pending.evidence),
      evidence: pending.evidence,
      observedAt: now,
    } as const
    try {
      const verificationLeaseId = pending.decision?.kind === 'verify' ? pending.decision.leaseId : undefined
      const record = verificationLeaseId !== undefined
        ? await this.#ctx.expFirewall.settleLease({
            operationId: observation.operationId,
            leaseId: verificationLeaseId,
            ownerPrincipalId: pending.principalId,
            observation,
            newClaimId: createClaimId(),
            now,
          })
        : await this.#ctx.expFirewall.record({
            operationId: observation.operationId,
            observation,
            newClaimId: createClaimId(),
            now,
          })
      if (verificationLeaseId !== undefined) this.#ownedLeases.delete(verificationLeaseId)
      const claim = 'replacementClaim' in record ? record.replacementClaim ?? record.claim : record.claim
      appendFirewallSessionEvent(sessionFor(exec), 'exp-firewall/observation', {
        operationId: observation.operationId,
        observationId: observation.id,
        ...(claim === undefined ? {} : { claimId: claim.id }),
        outcome: observation.outcome,
        fingerprint: observation.fingerprint,
      })
      for (const transition of record.transitions) {
        appendFirewallSessionEvent(sessionFor(exec), 'exp-firewall/transition', {
          operationId: observation.operationId,
          ...transition,
        })
      }
    } catch (error) {
      this.#diagnose('post-execution Store mutation failed', error)
      // Post-execution Store failure never rewrites the tool's authoritative result.
    }

    const notice = pending.decision === undefined
      ? undefined
      : projectFirewallDecisionNotice(
          {
            operationId: pending.decisionOperationId,
            ...('claimId' in pending.decision && pending.decision.claimId !== undefined
              ? { claimId: pending.decision.claimId }
              : {}),
            decision: pending.decision.kind,
            reason: pending.decision.reason,
          },
          this.#config.redaction.maxPreviewChars,
        )
    if (notice === undefined || delegated.kind !== 'accept' || delegated.value !== undefined) return delegated
    if (pending.decision?.kind === 'warn') {
      try {
        await this.#ctx.expFirewall.recordWarning({
          operationId: createOperationId(),
          claimId: pending.decision.claimId,
          now: toUtcIso(Date.now()),
        })
      } catch (error) {
        this.#diagnose('model-visible warning counter failed', error)
      }
    }
    return { ...delegated, content: [...(delegated.content ?? result.content), { type: 'text', text: notice }] }
  }

  observeFile(target: FsTarget, observation: FsObservation, actor: object | undefined): void {
    const pending = actor === undefined ? undefined : this.#pending.get(actor)
    const witness = this.#cache.observe(target, observation, pending?.modelPathKey)
    if (pending?.actionKind === 'file-read') {
      const args = objectValue((actor as ToolExecution).arguments)
      const action = canonicalizeFileReadAction({
        tool: (actor as ToolExecution).name,
        path: args?.path,
        workdir: args?.workdir,
        sessionCwd: sessionCwd(actor as ToolExecution),
        providerDisplayPath: target.displayPath,
      })
      pending.fingerprint = fingerprintAction(action)
      pending.preview = createPreview(action.path, this.#config.redaction.maxPreviewChars)
      pending.evidence = [witness]
    }
    this.#invalidationQueue.enqueue(() =>
      this.#ctx.expFirewall.invalidateClaims({
        operationId: createOperationId(),
        evidence: [witness],
        now: toUtcIso(Date.now()),
      }),
    )
  }

  async stop(): Promise<void> {
    if (this.#stopPromise !== undefined) return this.#stopPromise
    this.#stopPromise = this.#stop()
    return this.#stopPromise
  }

  async #stop(): Promise<void> {
    this.#accepting = false
    this.#ctx.expFirewall.closeSubscriptions()
    await this.#invalidationQueue.stopAndDrain()
    const now = toUtcIso(Date.now())
    await Promise.allSettled(
      [...this.#ownedLeases].map(async ([leaseId, ownerPrincipalId]) => {
        try {
          await this.#ctx.expFirewall.releaseLease({
            kind: 'release-lease',
            operationId: createOperationId(),
            leaseId,
            ownerPrincipalId,
            cause: 'released',
            now,
          })
        } catch (error) {
          this.#diagnose('owned verification lease release failed', error)
        }
      }),
    )
    this.#ownedLeases.clear()
    this.#cache.clear()
  }
}

/**
 * Register pre/post tool policy and synchronous filesystem observation effects.
 * @param ctx - Cordis context with the Exp Firewall Service.
 * @param input - Plugin configuration resolved once at loading.
 */
export function apply(ctx: Context, input: Parameters<typeof resolveConfig>[0] = {}): void {
  const consumer = new ExperienceFirewallConsumer(ctx, resolveConfig(input))
  ctx.on('tools/pre-execute', (exec, next) => consumer.preExecute(exec, next))
  ctx.on('tools/post-execute', (exec, result, next) => consumer.postExecute(exec, result, next))
  ctx.on('fs/observed', (target, observation, actor) => consumer.observeFile(target, observation, actor))
  ctx.effect(() => () => consumer.stop(), 'exp-firewall Consumer teardown')
}
