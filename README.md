# Exp Firewall

![Evidence-gated recovery demo](assets/evidence-recovery.gif)

Exp Firewall is a local, provenance-aware shared-experience firewall for DeepSeek Harness agents. It records structured command and file-read outcomes as immutable Observations, forms revocable Claims only from independent principals, and uses filesystem Evidence plus a single verification Lease to prevent stale experience from blocking a recovered environment.

[中文](README.zh.md)

## Install and compose

Install the package into a DSH profile:

```sh
dsh plugin --profile <profile> add exp-firewall
```

To install a downloaded release artifact instead:

```sh
dsh plugin --profile <profile> add ./exp-firewall-0.1.0.tgz
```

The Bundle mounts `exp-firewall/service` before the `exp-firewall` policy Consumer. The `exp-firewall/dashboard` row is disabled by default; enable it only in a Web profile that provides `webServer`. Published packages contain prebuilt ESM and TypeScript declarations.

Remove the three `exp-firewall-service`, `exp-firewall`, and optional `exp-firewall-dashboard` rows (or remove the plugin through DSH) to unload it. Unload stops new policy work, removes read subscriptions, drains Evidence invalidation, safely releases process-owned Leases, drains Store writes, and closes SQLite.

## Configuration

Default configuration:

```yaml
mode: warn
dataDir: .dsh/exp-firewall
minIndependentSupporters: 2
observationTtlMs: 300000
verificationLeaseTtlMs: 60000
storeBusyDeadlineMs: 2000
enforceStoreFailure: allow
commandTools: [bash, pwsh]
readTools: [read]
policies:
  command: { enforce: true }
  file-read: { enforce: true }
dashboard:
  enabled: true
  host: 127.0.0.1
  pollIntervalMs: 1000
redaction:
  maxPreviewChars: 160
```

- `observe` records and allows.
- `warn` (default) records, allows, and attaches stable model-visible notices.
- `enforce` may deny corroborated failures, grant one verification Lease after Evidence changes, or return `verification-in-progress` while another principal owns it.

Store failures are fail-open by default. Only `mode: enforce` with `enforceStoreFailure: deny` is fail-closed. Per-kind `policies.*.enforce: false` maps that action kind back to warn behavior.

## Decision and model experience

A single Principal can create only a `suspected` Claim. A second independent Principal with matching Evidence can make it `corroborated`. Missing or incomparable Evidence never produces `deny`. Changed Evidence makes the old Claim `stale` before retry; one Principal receives a Lease and others wait. A structured successful verification resolves the Claim, while a structured failure supersedes it and starts a new Evidence-epoch Claim.

Only structured contracts classify outcomes: commands require an integer `exitCode`; file-read consensus failure requires `FS_NOT_FOUND`. Human-readable output is never parsed. Every visible warning, denial, verification, and transition is correlated through operation, Observation, Claim, Session, and tool-call identifiers.

## Read-only surfaces

The optional Dashboard API exposes only:

```text
GET /plugins/exp-firewall/api/summary
GET /plugins/exp-firewall/api/claims
GET /plugins/exp-firewall/api/claims/:id
GET /plugins/exp-firewall/api/events
```

The browser plugin registers a read-only Exp Firewall tab in DSH Web Settings. It polls once per second by default and renders Overview, a filtered/paginated Claim Explorer, and Claim Detail provenance. The CLI is also read-only:

```sh
exp-firewall status [--scope <scope>]
exp-firewall claims [--status <status>] [--scope <scope>]
exp-firewall claim <id>
exp-firewall events [--claim <id>]
```

Set `EXP_FIREWALL_DATA_DIR` when invoking the standalone CLI outside its default profile directory.

## Data and privacy

SQLite runs in WAL mode under a `0700` data directory with a `0600` database file on platforms that support POSIX modes. The Store persists full fingerprints, Evidence, redacted bounded previews, structured failure codes, and provenance—never raw tool output or canonical raw actions. HTTP, CLI, and browser DTOs expose only this read model. Dashboard failure and subscriber exceptions are isolated from policy writes. Counters are directly observed facts; the product does not estimate token savings.

## Demos and verification

```sh
pnpm install
pnpm run check
pnpm run demo:consensus
pnpm run demo:evidence
pnpm run demo:concurrent
```

The keyless Evidence-recovery demo uses the real Cordis Loader, Session, ToolRuntime, Provider, Consumer, and structured file tool. All three scenarios compare their output with deterministic snapshots. See the [demo guide](demos/README.md).

## Current limitations

Exp Firewall currently supports exact command and file-read fingerprints on one local SQLite Store. It does not provide malicious-agent identity resistance, semantic clustering, cross-machine aggregation, automatic repair, causal recovery inference, live dashboard push, write APIs, or raw report export.
