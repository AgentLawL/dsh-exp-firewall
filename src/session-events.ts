import { createPreview } from './redaction.ts'
import type {
  ClaimId,
  ClaimStatus,
  Decision,
  Fingerprint,
  ObservationId,
  OperationId,
} from './types/domain.ts'

/** Durable Session payload for one immutable tool outcome. */
export interface FirewallObservationSessionEvent {
  operationId: OperationId
  observationId: ObservationId
  claimId?: ClaimId
  outcome: 'success' | 'failure'
  fingerprint: Fingerprint
}

/** Durable Session payload for one explainable policy Decision. */
export interface FirewallDecisionSessionEvent {
  operationId: OperationId
  claimId?: ClaimId
  decision: Decision['kind']
  reason: Decision['reason']
  revision?: number
}

/** Durable Session payload for one Claim state transition. */
export interface FirewallTransitionSessionEvent {
  operationId: OperationId
  claimId: ClaimId
  from: ClaimStatus
  to: ClaimStatus
  revision: number
}

/** Exp Firewall additions to the append-only Session event vocabulary. */
export interface ExperienceFirewallSessionEvents {
  'exp-firewall/observation': FirewallObservationSessionEvent
  'exp-firewall/decision': FirewallDecisionSessionEvent
  'exp-firewall/transition': FirewallTransitionSessionEvent
}

declare module '@deepseek-ai/dsh-session/types' {
  interface SessionEventMap {
    /**
     * One immutable Exp Firewall tool outcome with database correlation IDs.
     * Log-only; paired tool results carry any model-visible text.
     */
    'exp-firewall/observation': FirewallObservationSessionEvent
    /**
     * One policy result recorded before it becomes model-visible or changes dispatch.
     * Log-only; replay uses its stable reason rather than inferring policy again.
     */
    'exp-firewall/decision': FirewallDecisionSessionEvent
    /**
     * One revision-guarded Claim lifecycle change.
     * Log-only and reconstructable independently of the dashboard.
     */
    'exp-firewall/transition': FirewallTransitionSessionEvent
  }
}

/** Minimal Session append capability used without coupling the pure core to DSH. */
export interface FirewallSessionAppender {
  append<Type extends keyof ExperienceFirewallSessionEvents>(
    type: Type,
    data: ExperienceFirewallSessionEvents[Type],
  ): unknown
}

/** Minimal replay event envelope read from a durable Session log. */
export interface FirewallReplayEvent {
  type: string
  data: unknown
}

/**
 * Append one typed Exp Firewall Session event.
 * @param session - Attempting tool call's Session.
 * @param type - Stable event type.
 * @param data - JSON-serializable correlated payload.
 */
export function appendFirewallSessionEvent<Type extends keyof ExperienceFirewallSessionEvents>(
  session: FirewallSessionAppender,
  type: Type,
  data: ExperienceFirewallSessionEvents[Type],
): void {
  session.append(type, data)
}

/**
 * Replay only Exp Firewall events while preserving log order.
 * @param events - Complete durable Session event sequence.
 * @returns Recognized event type/payload pairs.
 */
export function replayFirewallSessionEvents(
  events: readonly FirewallReplayEvent[],
): Array<{ [Type in keyof ExperienceFirewallSessionEvents]: { type: Type; data: ExperienceFirewallSessionEvents[Type] } }[keyof ExperienceFirewallSessionEvents]> {
  const recognized = new Set<keyof ExperienceFirewallSessionEvents>([
    'exp-firewall/observation',
    'exp-firewall/decision',
    'exp-firewall/transition',
  ])
  return events.filter(
    (event): event is {
      [Type in keyof ExperienceFirewallSessionEvents]: {
        type: Type
        data: ExperienceFirewallSessionEvents[Type]
      }
    }[keyof ExperienceFirewallSessionEvents] => recognized.has(event.type as keyof ExperienceFirewallSessionEvents),
  )
}

/**
 * Project a stable, bounded model-facing Decision notice from the logged payload.
 * @param event - Previously appended Decision event.
 * @param maxChars - Final Unicode code-point cap.
 * @returns Notice for warn, deny, verify, or wait; undefined for silent allow.
 */
export function projectFirewallDecisionNotice(
  event: FirewallDecisionSessionEvent,
  maxChars: number,
): string | undefined {
  if (event.decision === 'allow') return undefined
  const claim = event.claimId === undefined ? '' : ` claim=${event.claimId}`
  return createPreview(
    `[exp-firewall] decision=${event.decision} reason=${event.reason}${claim} operation=${event.operationId}`,
    maxChars,
  )
}
