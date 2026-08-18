import type { DatabaseSync } from 'node:sqlite'

import type { Config } from './config.ts'
import { compareEvidence } from './evidence.ts'
import { stableJson, type JsonValue } from './fingerprint.ts'
import { actionPolicyEnforced, mapDeploymentPolicy, recommendPolicy } from './policy.ts'
import { insertAuditEvent, withOperationReceipt } from './receipts.ts'
import { reduceFirewall } from './reducer.ts'
import { openSqliteDatabase, type SqliteDatabase } from './store-sqlite.ts'
import type {
  ClaimSupporter,
  DecisionRequest,
  ExperienceFirewallStore,
  FirewallEvent,
  FirewallState,
  InvalidateClaimsRequest,
  InvalidateClaimsResult,
  PureAuditEvent,
  RecordObservationRequest,
  RecordResult,
  RecordWarningRequest,
  ReducerResult,
  ReleaseLeaseCommand,
  SettleLeaseRequest,
  SettleResult,
} from './store.ts'
import type {
  Claim,
  ClaimDetail,
  ClaimFilter,
  ClaimId,
  ClaimView,
  Decision,
  EventFilter,
  EvidenceWitness,
  FirewallSummary,
  Page,
  SummaryFilter,
  VerificationLease,
} from './types/domain.ts'
import { FirewallError } from './types/errors.ts'

type SqliteValue = string | number | bigint | null

interface ClaimRow {
  id: string
  scope: string
  action_kind: Claim['actionKind']
  fingerprint: string
  evidence_epoch: string
  evidence_json: string
  preview: string
  status: Claim['status']
  supporter_count: number
  revision: number
  is_current: number
  created_at: string
  updated_at: string
}

function claimFromRow(row: ClaimRow): Claim {
  return {
    id: row.id as Claim['id'],
    scope: row.scope,
    actionKind: row.action_kind,
    fingerprint: row.fingerprint as Claim['fingerprint'],
    evidenceEpoch: row.evidence_epoch as Claim['evidenceEpoch'],
    evidence: JSON.parse(row.evidence_json) as EvidenceWitness[],
    preview: row.preview,
    status: row.status,
    supporterCount: row.supporter_count,
    revision: row.revision,
    isCurrent: row.is_current === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

function loadState(database: DatabaseSync): FirewallState {
  const observations = database.prepare('SELECT * FROM observations ORDER BY observed_at, id').all().map((row) => {
    const value = row as Record<string, SqliteValue>
    return {
      id: value.id as never,
      operationId: value.operation_id as never,
      sessionId: value.session_id as string,
      principalId: value.principal_id as never,
      ...(value.tool_call_id === null ? {} : { toolCallId: value.tool_call_id as string }),
      scope: value.scope as string,
      actionKind: value.action_kind as 'command' | 'file-read',
      fingerprint: value.fingerprint as never,
      preview: value.preview as string,
      outcome: value.outcome as 'success' | 'failure',
      ...(value.failure_code === null ? {} : { failureCode: value.failure_code as string }),
      evidenceEpoch: value.evidence_epoch as never,
      evidence: JSON.parse(value.evidence_json as string) as EvidenceWitness[],
      observedAt: value.observed_at as string,
    }
  })
  const claims = (database.prepare('SELECT * FROM claims ORDER BY created_at, id').all() as unknown as ClaimRow[]).map(
    claimFromRow,
  )
  const supporters = database.prepare('SELECT * FROM claim_supporters ORDER BY claim_id, principal_id').all().map((row) => {
    const value = row as Record<string, SqliteValue>
    return {
      claimId: value.claim_id as ClaimSupporter['claimId'],
      principalId: value.principal_id as ClaimSupporter['principalId'],
      lastObservedAt: value.last_observed_at as string,
    }
  })
  const leases = database.prepare('SELECT * FROM verification_leases ORDER BY id').all().map((row) => {
    const value = row as Record<string, SqliteValue>
    return {
      id: value.id as VerificationLease['id'],
      claimId: value.claim_id as VerificationLease['claimId'],
      ownerPrincipalId: value.owner_principal_id as VerificationLease['ownerPrincipalId'],
      evidenceEpoch: value.evidence_epoch as VerificationLease['evidenceEpoch'],
      expiresAt: value.expires_at as string,
      ...(value.outcome === null ? {} : { outcome: value.outcome as NonNullable<VerificationLease['outcome']> }),
      ...(value.settled_at === null ? {} : { settledAt: value.settled_at as string }),
    }
  })
  return { observations, claims, supporters, leases, events: [] }
}

function insertObservation(database: DatabaseSync, observation: FirewallState['observations'][number]): void {
  database
    .prepare(
      `INSERT INTO observations(
        id, operation_id, session_id, principal_id, tool_call_id, scope, action_kind, fingerprint,
        preview, outcome, failure_code, evidence_epoch, evidence_json, observed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      observation.id,
      observation.operationId,
      observation.sessionId,
      observation.principalId,
      observation.toolCallId ?? null,
      observation.scope,
      observation.actionKind,
      observation.fingerprint,
      observation.preview,
      observation.outcome,
      observation.failureCode ?? null,
      observation.evidenceEpoch,
      stableJson(observation.evidence),
      observation.observedAt,
    )
}

function insertClaim(database: DatabaseSync, claim: Claim): void {
  database
    .prepare(
      `INSERT INTO claims(
        id, scope, action_kind, fingerprint, evidence_epoch, evidence_json, preview, status,
        supporter_count, revision, is_current, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      claim.id,
      claim.scope,
      claim.actionKind,
      claim.fingerprint,
      claim.evidenceEpoch,
      stableJson(claim.evidence),
      claim.preview,
      claim.status,
      claim.supporterCount,
      claim.revision,
      claim.isCurrent ? 1 : 0,
      claim.createdAt,
      claim.updatedAt,
    )
}

function updateClaim(database: DatabaseSync, claim: Claim, expectedRevision: number): void {
  const result = database
    .prepare(
      `UPDATE claims SET
        scope = ?, action_kind = ?, fingerprint = ?, evidence_epoch = ?, evidence_json = ?, preview = ?,
        status = ?, supporter_count = ?, revision = ?, is_current = ?, created_at = ?, updated_at = ?
       WHERE id = ? AND revision = ?`,
    )
    .run(
      claim.scope,
      claim.actionKind,
      claim.fingerprint,
      claim.evidenceEpoch,
      stableJson(claim.evidence),
      claim.preview,
      claim.status,
      claim.supporterCount,
      claim.revision,
      claim.isCurrent ? 1 : 0,
      claim.createdAt,
      claim.updatedAt,
      claim.id,
      expectedRevision,
    )
  if (result.changes !== 1) {
    throw new FirewallError('REVISION_CONFLICT', 'Claim revision changed during the transaction; retry the operation.')
  }
}

function durableEventKind(event: PureAuditEvent): string {
  return event.kind === 'claim-transition' ? `${event.kind}/${event.to}` : event.kind
}

function eventBody(event: PureAuditEvent): Record<string, JsonValue | undefined> {
  const { kind: _kind, operationId: _operationId, occurredAt: _occurredAt, claimId: _claimId, ...body } = event
  return body as Record<string, JsonValue | undefined>
}

function persistReducerResult(
  database: DatabaseSync,
  before: FirewallState,
  result: Extract<ReducerResult, { kind: 'applied' }>,
): void {
  const priorObservationIds = new Set(before.observations.map((observation) => observation.id))
  for (const observation of result.state.observations) {
    if (!priorObservationIds.has(observation.id)) insertObservation(database, observation)
  }

  const priorClaims = new Map(before.claims.map((claim) => [claim.id, claim]))
  for (const claim of result.state.claims) {
    const prior = priorClaims.get(claim.id)
    if (prior === undefined) insertClaim(database, claim)
    else if (stableJson(prior) !== stableJson(claim)) updateClaim(database, claim, prior.revision)
  }

  for (const supporter of result.state.supporters) {
    database
      .prepare(
        `INSERT INTO claim_supporters(claim_id, principal_id, last_observed_at) VALUES (?, ?, ?)
         ON CONFLICT(claim_id, principal_id) DO UPDATE SET last_observed_at = excluded.last_observed_at`,
      )
      .run(supporter.claimId, supporter.principalId, supporter.lastObservedAt)
  }

  const priorLeases = new Map(before.leases.map((lease) => [lease.id, lease]))
  for (const lease of result.state.leases) {
    const prior = priorLeases.get(lease.id)
    if (prior === undefined) {
      database
        .prepare(
          `INSERT INTO verification_leases(
            id, claim_id, owner_principal_id, evidence_epoch, expires_at, outcome, settled_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          lease.id,
          lease.claimId,
          lease.ownerPrincipalId,
          lease.evidenceEpoch,
          lease.expiresAt,
          lease.outcome ?? null,
          lease.settledAt ?? null,
        )
    } else if (stableJson(prior) !== stableJson(lease)) {
      database
        .prepare('UPDATE verification_leases SET outcome = ?, settled_at = ? WHERE id = ? AND outcome IS NULL')
        .run(lease.outcome ?? null, lease.settledAt ?? null, lease.id)
    }
  }

  for (const event of result.events) {
    insertAuditEvent(database, {
      operationId: event.operationId,
      ...('claimId' in event && event.claimId !== undefined ? { claimId: event.claimId } : {}),
      kind: durableEventKind(event),
      body: eventBody(event),
      occurredAt: event.occurredAt,
    })
  }
}

function requireApplied(result: ReducerResult): Extract<ReducerResult, { kind: 'applied' }> {
  if (result.kind === 'rejected') throw result.error
  if (result.kind === 'duplicate') {
    throw new FirewallError('INVARIANT_VIOLATION', 'Unexpected duplicate transition inside a new operation receipt.')
  }
  return result
}

function claimTransitions(result: Extract<ReducerResult, { kind: 'applied' }>) {
  return result.events.flatMap((event) =>
    event.kind === 'claim-transition'
      ? [{ claimId: event.claimId, from: event.from, to: event.to, revision: event.revision }]
      : [],
  )
}

function currentClaim(state: FirewallState, request: Pick<DecisionRequest, 'scope' | 'fingerprint'>): Claim | undefined {
  return state.claims.find(
    (claim) => claim.isCurrent && claim.scope === request.scope && claim.fingerprint === request.fingerprint,
  )
}

function checkSignal(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw signal.reason ?? new DOMException('The read was aborted.', 'AbortError')
}

function pageInput(cursor: string | undefined, limit: number | undefined): { offset: number; limit: number } {
  const offset = cursor === undefined ? 0 : Number(cursor)
  const actualLimit = limit ?? 50
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(actualLimit) || actualLimit < 1 || actualLimit > 200) {
    throw new FirewallError('INVALID_ACTION', 'Pagination requires a non-negative cursor and a limit from 1 to 200.')
  }
  return { offset, limit: actualLimit }
}

/** SQLite-backed Exp Firewall Service Provider. */
export class SqliteExperienceFirewallStore implements ExperienceFirewallStore {
  readonly #config: Config
  readonly #database: SqliteDatabase
  readonly #pendingWrites = new Set<Promise<unknown>>()
  #acceptingWrites = true
  #closed = false

  /**
   * Open the configured durable Store.
   * @param config - Fully resolved configuration.
   */
  constructor(config: Config) {
    this.#config = structuredClone(config)
    this.#database = openSqliteDatabase(config.dataDir)
    this.#database.connection.exec(`PRAGMA busy_timeout = ${Math.min(config.storeBusyDeadlineMs, 25)}`)
  }

  #requireOpen(): DatabaseSync {
    if (this.#closed) throw new FirewallError('STORE_CORRUPT', 'The Exp Firewall Store is closed.')
    return this.#database.connection
  }

  #write<Result>(
    operationId: DecisionRequest['operationId'],
    request: unknown,
    createdAt: string,
    mutate: (database: DatabaseSync) => Result,
  ): Promise<Result> {
    if (!this.#acceptingWrites) {
      return Promise.reject(new FirewallError('STORE_CORRUPT', 'The Exp Firewall Store is shutting down and no longer accepts writes.'))
    }
    const pending = this.#runWrite(operationId, request, createdAt, mutate)
    this.#pendingWrites.add(pending)
    pending.then(
      () => this.#pendingWrites.delete(pending),
      () => this.#pendingWrites.delete(pending),
    )
    return pending
  }

  async #runWrite<Result>(
    operationId: DecisionRequest['operationId'],
    request: unknown,
    createdAt: string,
    mutate: (database: DatabaseSync) => Result,
  ): Promise<Result> {
    const deadline = Date.now() + this.#config.storeBusyDeadlineMs
    let revisionAttempts = 0
    for (;;) {
      try {
        return withOperationReceipt(this.#requireOpen(), operationId, request, createdAt, mutate).result
      } catch (error) {
        if (!(error instanceof FirewallError)) throw error
        if (error.code === 'REVISION_CONFLICT' && revisionAttempts < 3) {
          revisionAttempts += 1
          continue
        }
        if (error.code === 'STORE_BUSY') {
          const remaining = deadline - Date.now()
          if (remaining <= 0) throw error
          await new Promise((resolve) => setTimeout(resolve, Math.min(remaining, 10)))
          continue
        }
        throw error
      }
    }
  }

  async decide(request: DecisionRequest): Promise<Decision> {
    const database = this.#requireOpen()
    return this.#write(request.operationId, request, request.now, (connection) => {
      let state = loadState(connection)
      let claim = currentClaim(state, request)
      if (
        claim !== undefined &&
        (claim.status === 'suspected' || claim.status === 'corroborated') &&
        compareEvidence(claim.evidence, request.evidence) === 'changed'
      ) {
        const transition = requireApplied(
          reduceFirewall(state, {
            kind: 'invalidate-evidence',
            operationId: request.operationId,
            scope: request.scope,
            fingerprint: request.fingerprint,
            currentEvidence: request.evidence,
            now: request.now,
          }),
        )
        persistReducerResult(connection, state, transition)
        state = transition.state
        claim = currentClaim(state, request)
      }

      const activeLease = claim === undefined
        ? undefined
        : state.leases.find((lease) => lease.claimId === claim!.id && lease.outcome === undefined)
      const recommendation = recommendPolicy({
        ...(claim === undefined ? {} : { claim }),
        supporters: state.supporters,
        ...(activeLease === undefined ? {} : { activeLease }),
        currentEvidence: request.evidence,
        principalId: request.principalId,
        now: request.now,
        observationTtlMs: this.#config.observationTtlMs,
        minIndependentSupporters: this.#config.minIndependentSupporters,
      })
      let evaluation = mapDeploymentPolicy(recommendation, {
        mode: this.#config.mode,
        actionKind: request.actionKind,
        enforce: actionPolicyEnforced(this.#config, request.actionKind),
      })

      if (evaluation.shouldAcquireLease) {
        if (claim === undefined || request.candidateLease === undefined) {
          throw new FirewallError('INVARIANT_VIOLATION', 'Enforce verification requires a caller-generated lease candidate.')
        }
        const leaseTransition = requireApplied(
          reduceFirewall(state, {
            kind: 'grant-lease',
            operationId: request.operationId,
            claimId: claim.id,
            lease: { ...request.candidateLease, claimId: claim.id },
            now: request.now,
          }),
        )
        persistReducerResult(connection, state, leaseTransition)
        state = leaseTransition.state
        evaluation = mapDeploymentPolicy(recommendation, {
          mode: this.#config.mode,
          actionKind: request.actionKind,
          enforce: actionPolicyEnforced(this.#config, request.actionKind),
          grantedLeaseId: request.candidateLease.id,
        })
      }

      const decision = evaluation.decision
      const decisionClaimId = 'claimId' in decision ? decision.claimId : undefined
      insertAuditEvent(connection, {
        operationId: request.operationId,
        ...(decisionClaimId === undefined ? {} : { claimId: decisionClaimId }),
        kind: 'decision',
        body: decision as unknown as Record<string, JsonValue>,
        occurredAt: request.now,
      })
      if (decision.kind === 'deny' || decision.kind === 'wait') {
        insertAuditEvent(connection, {
          operationId: request.operationId,
          claimId: decision.claimId,
          kind: decision.kind === 'deny' ? 'call-denied' : 'verification-wait',
          body: { reason: decision.reason },
          occurredAt: request.now,
        })
      }
      if (
        decisionClaimId !== undefined &&
        state.supporters.some(
          (supporter) => supporter.claimId === decisionClaimId && supporter.principalId !== request.principalId,
        )
      ) {
        insertAuditEvent(connection, {
          operationId: request.operationId,
          claimId: decisionClaimId,
          kind: 'cross-agent-hit',
          body: {},
          occurredAt: request.now,
        })
      }
      return decision
    })
  }

  async record(request: RecordObservationRequest): Promise<RecordResult> {
    const database = this.#requireOpen()
    return this.#write(request.operationId, request, request.now, (connection) => {
      const state = loadState(connection)
      const result = reduceFirewall(state, {
        kind: 'record-observation',
        ...request,
        observationTtlMs: this.#config.observationTtlMs,
        minIndependentSupporters: this.#config.minIndependentSupporters,
      })
      if (result.kind === 'rejected') throw result.error
      if (result.kind === 'duplicate') {
        return { observation: request.observation, duplicate: true, transitions: [] }
      }
      persistReducerResult(connection, state, result)
      return {
        observation: request.observation,
        ...(result.claim === undefined ? {} : { claim: result.claim }),
        duplicate: false,
        transitions: claimTransitions(result),
      }
    })
  }

  /** Persist one model-visible warning counter event idempotently. */
  async recordWarning(request: RecordWarningRequest): Promise<{ recorded: true }> {
    return this.#write(request.operationId, request, request.now, (connection) => {
      insertAuditEvent(connection, {
        operationId: request.operationId,
        ...(request.claimId === undefined ? {} : { claimId: request.claimId }),
        kind: 'warning-emitted',
        body: {},
        occurredAt: request.now,
      })
      return { recorded: true }
    })
  }

  async settleLease(request: SettleLeaseRequest): Promise<SettleResult> {
    const database = this.#requireOpen()
    return this.#write(request.operationId, request, request.now, (connection) => {
      const state = loadState(connection)
      const result = requireApplied(reduceFirewall(state, { kind: 'settle-lease', ...request }))
      persistReducerResult(connection, state, result)
      if (result.lease === undefined || result.claim === undefined) {
        throw new FirewallError('INVARIANT_VIOLATION', 'Lease settlement did not return its Lease and Claim.')
      }
      const oldClaim = state.claims.find((claim) => claim.id === result.lease!.claimId)
      return {
        lease: result.lease,
        claim: oldClaim?.id === result.claim.id ? result.claim : result.state.claims.find((claim) => claim.id === oldClaim?.id)!,
        ...(oldClaim?.id === result.claim.id ? {} : { replacementClaim: result.claim }),
        transitions: claimTransitions(result),
      }
    })
  }

  /**
   * Release an owned lease or settle an expired lease without a success conclusion.
   * @param request - Explicit release/expiry reducer command.
   * @returns Settled lease and stale Claim.
   */
  async releaseLease(request: ReleaseLeaseCommand): Promise<{ lease: VerificationLease; claim: Claim }> {
    const database = this.#requireOpen()
    return this.#write(request.operationId, request, request.now, (connection) => {
      const state = loadState(connection)
      const result = requireApplied(reduceFirewall(state, request))
      persistReducerResult(connection, state, result)
      if (result.lease === undefined || result.claim === undefined) {
        throw new FirewallError('INVARIANT_VIOLATION', 'Lease release did not return its Lease and Claim.')
      }
      return { lease: result.lease, claim: result.claim }
    })
  }

  /**
   * Mark every current Claim affected by a changed filesystem Witness stale.
   * @param request - Latest Evidence and explicit operation/time.
   * @returns IDs whose status changed.
   */
  async invalidateClaims(request: InvalidateClaimsRequest): Promise<InvalidateClaimsResult> {
    return this.#write(request.operationId, request, request.now, (connection) => {
      let state = loadState(connection)
      const claimIds: ClaimId[] = []
      for (const candidate of state.claims.filter((claim) => claim.isCurrent)) {
        if (!candidate.evidence.some((witness) => request.evidence.some((current) => current.key === witness.key))) {
          continue
        }
        const result = reduceFirewall(state, {
          kind: 'invalidate-evidence',
          operationId: request.operationId,
          scope: candidate.scope,
          fingerprint: candidate.fingerprint,
          currentEvidence: request.evidence,
          now: request.now,
        })
        if (result.kind === 'rejected') throw result.error
        if (result.kind === 'applied' && result.events.length > 0) {
          persistReducerResult(connection, state, result)
          state = result.state
          claimIds.push(candidate.id)
        }
      }
      return { claimIds }
    })
  }

  async summary(filter: SummaryFilter = {}): Promise<FirewallSummary> {
    const database = this.#requireOpen()
    checkSignal(filter.signal)
    const claimRows = database
      .prepare(
        `SELECT status, COUNT(*) AS count FROM claims
         WHERE is_current = 1 AND (? IS NULL OR scope = ?) GROUP BY status`,
      )
      .all(filter.scope ?? null, filter.scope ?? null) as Array<{ status: Claim['status']; count: number }>
    const statusCount = new Map(claimRows.map((row) => [row.status, row.count]))
    const countEvent = (kind: string): number => {
      const row = database
        .prepare(
          `SELECT COUNT(*) AS count FROM events e LEFT JOIN claims c ON c.id = e.claim_id
           WHERE e.kind = ? AND (? IS NULL OR c.scope = ?)`,
        )
        .get(kind, filter.scope ?? null, filter.scope ?? null) as { count: number }
      return row.count
    }
    const result: FirewallSummary = {
      suspectedClaims: statusCount.get('suspected') ?? 0,
      corroboratedClaims: statusCount.get('corroborated') ?? 0,
      staleClaims: (statusCount.get('stale') ?? 0) + (statusCount.get('verifying') ?? 0),
      resolvedClaims: statusCount.get('resolved') ?? 0,
      warningsEmitted: countEvent('warning-emitted'),
      callsDenied: countEvent('call-denied'),
      verificationWaits: countEvent('verification-wait'),
      leasesGranted: countEvent('lease-granted'),
      crossAgentHits: countEvent('cross-agent-hit'),
    }
    checkSignal(filter.signal)
    return result
  }

  async listClaims(filter: ClaimFilter = {}): Promise<Page<ClaimView>> {
    const database = this.#requireOpen()
    checkSignal(filter.signal)
    const { offset, limit } = pageInput(filter.cursor, filter.limit)
    const rows = database
      .prepare(
        `SELECT * FROM claims WHERE (? IS NULL OR scope = ?) AND (? IS NULL OR status = ?)
         ORDER BY updated_at DESC, id LIMIT ? OFFSET ?`,
      )
      .all(filter.scope ?? null, filter.scope ?? null, filter.status ?? null, filter.status ?? null, limit + 1, offset) as unknown as ClaimRow[]
    const claims = rows.slice(0, limit).map(claimFromRow).map(({ evidence: _e, evidenceEpoch: _ee, ...view }) => view)
    checkSignal(filter.signal)
    return { items: claims, ...(rows.length > limit ? { nextCursor: String(offset + limit) } : {}) }
  }

  async getClaim(id: ClaimId, signal?: AbortSignal): Promise<ClaimDetail | undefined> {
    const database = this.#requireOpen()
    checkSignal(signal)
    const row = database.prepare('SELECT * FROM claims WHERE id = ?').get(id) as unknown as ClaimRow | undefined
    if (row === undefined) return undefined
    const claim = claimFromRow(row)
    const observations = loadState(database).observations.filter(
      (observation) => observation.scope === claim.scope && observation.fingerprint === claim.fingerprint,
    )
    const lease = loadState(database).leases.find((candidate) => candidate.claimId === claim.id && candidate.outcome === undefined)
    const { evidence, evidenceEpoch, ...view } = claim
    checkSignal(signal)
    return { ...view, evidence, evidenceEpoch, observations, ...(lease === undefined ? {} : { lease }) }
  }

  async listEvents(filter: EventFilter = {}): Promise<Page<FirewallEvent>> {
    const database = this.#requireOpen()
    checkSignal(filter.signal)
    const { offset, limit } = pageInput(filter.cursor, filter.limit)
    const rows = database
      .prepare(
        `SELECT * FROM events WHERE (? IS NULL OR claim_id = ?) ORDER BY occurred_at DESC, id LIMIT ? OFFSET ?`,
      )
      .all(filter.claimId ?? null, filter.claimId ?? null, limit + 1, offset) as Array<Record<string, SqliteValue>>
    const items = rows.slice(0, limit).map((row) => ({
      id: row.id as string,
      operationId: row.operation_id as FirewallEvent['operationId'],
      ...(row.claim_id === null ? {} : { claimId: row.claim_id as ClaimId }),
      kind: row.kind as string,
      body: JSON.parse(row.body_json as string) as Record<string, unknown>,
      occurredAt: row.occurred_at as string,
    }))
    checkSignal(filter.signal)
    return { items, ...(rows.length > limit ? { nextCursor: String(offset + limit) } : {}) }
  }

  async shutdown(): Promise<void> {
    if (this.#closed) return
    this.#acceptingWrites = false
    await Promise.allSettled([...this.#pendingWrites])
    if (this.#closed) return
    this.#closed = true
    this.#database.close()
  }
}
