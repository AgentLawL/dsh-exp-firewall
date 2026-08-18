# Exp Firewall demos

Run the deterministic pure-core fixture without an API key:

```sh
pnpm run demo:m0
```

The fixture shows two independent failures reaching corroboration and an enforce-mode denial. Its output is checked against `consensus.snapshot.txt`.

Run the keyless real-Loader composition and its stable snapshot check with:

```sh
pnpm run demo:m2
pnpm run test:snapshot:m2
```

The M2 fixture mounts real Session and ToolRuntime services, then demonstrates consensus, enforcement, Evidence change, verification, and recovery without a model API key.
Set `EXP_FIREWALL_PACKAGE_ROOT` to an unpacked or installed package directory to run the same fixture against a release tarball instead of the workspace build.

The three deterministic scenarios are:

- `pnpm run demo:consensus` — independent supporter consensus.
- `pnpm run demo:evidence` — assembled Evidence change and successful recovery.
- `pnpm run demo:concurrent` — three contenders with one Lease owner and two waiters.

`scripts/render-hero-gif.sh` deterministically renders the verified Evidence-recovery transcript into the README animation. Set `EXP_FIREWALL_PYTHON` to a Python 3 environment with Pillow when it is not installed in the default interpreter.
