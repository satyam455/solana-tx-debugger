# Solana Debug

A private-first, read-only Solana transaction debugger.

`solana-debug` fetches or loads a transaction, normalizes it into a canonical
`TransactionTrace`, runs deterministic analysis, and emits an evidence-backed
report. It is designed as a debugger first: no wallet access, no signing, no
broadcasting, and no LLM/replay path in the current release.

## What It Does

- Inspect landed Solana transactions by signature.
- Support legacy, v0, and v1 transaction versions.
- Resolve static account keys and ALT-loaded account keys into canonical account
  indexes.
- Preserve signer/writable metadata.
- Capture transaction errors, logs, inner instructions, compute units, return
  data, slot, block time, and transaction version when available.
- Reconstruct CPI structure conservatively.
- Decode common instruction families:
  - System Program
  - Compute Budget
  - SPL Token
  - Token-2022
  - Associated Token Program
- Decode Anchor structured error logs such as
  `NonceAlreadyExists` / `Error Number: 6000`.
- Optionally load a local Anchor IDL to map custom errors to names/messages.
- Save local capture bundles for offline inspection.

## Safety Boundary

This project is deliberately read-only.

- No private keys.
- No seed phrases.
- No wallet/keypair files.
- No transaction signing.
- No `sendTransaction`.
- No replay or simulation yet.
- No LLM reasoning yet.

Online inspection uses Solana RPC `getTransaction` only.

## Install / Build

```bash
cargo build --workspace
```

Run checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

## Inspect A Real Transaction

```bash
cargo run -p solana-debug -- inspect <SIGNATURE> \
  --mode hybrid \
  --rpc-url https://api.mainnet-beta.solana.com \
  --json
```

Example:

```bash
cargo run -p solana-debug -- inspect \
  5owiYFGRQ9cVeYuLuByVoCiQiwxpS6B5wBqd1KeFrVGpG19zd6vPxRVwiyJVVffatHA1Rwe8xj91pT7cyao8Fhtz \
  --mode hybrid \
  --rpc-url https://api.mainnet-beta.solana.com \
  --json
```

For the example above, the debugger identifies:

```text
ANCHOR_NonceAlreadyExists
Anchor error 6000 (NonceAlreadyExists): Nonce already exists
```

## Failed Transactions

The debugger works on failed transactions that landed on-chain. These are
transactions that validators included in a block and executed, but whose runtime
result was an error.

It cannot inspect transactions that were dropped before landing, because those
do not have an on-chain `getTransaction` record.

## Use An Anchor IDL

If you have the failing program's Anchor IDL locally, pass it with `--idl`:

```bash
cargo run -p solana-debug -- inspect <SIGNATURE> \
  --mode hybrid \
  --rpc-url https://api.mainnet-beta.solana.com \
  --idl ./target/idl/my_program.json \
  --json
```

Do not pass placeholder paths like `path/to/program-idl.json`; the file must
exist on disk.

## Capture A Transaction For Offline Use

Capture saves a normalized trace, report, and capability manifest:

```bash
cargo run -p solana-debug -- capture <SIGNATURE> \
  --rpc-url https://api.mainnet-beta.solana.com \
  --out ./captures/my-debug-case
```

This writes:

```text
captures/my-debug-case/
├── manifest.json
├── report.json
└── trace.json
```

Inspect the saved trace offline:

```bash
cargo run -p solana-debug -- inspect \
  --tx-file ./captures/my-debug-case/trace.json \
  --json
```

Local captures are ignored by Git by default.

## Offline Fixture Mode

```bash
cargo run -p solana-debug -- inspect \
  --tx-file fixtures/trace/failing-token-program-mismatch.json \
  --json
```

## Output Highlights

Reports include:

- transaction status/version/slot/signature
- failure summary:
  - failing invocation id
  - top-level instruction index
  - failing program id
  - decoded instruction name when known
  - error code/message
  - instruction accounts
  - logs
- deterministic findings with evidence facts

## Workspace

- `crates/trace`: canonical transaction trace schema.
- `crates/rpc`: online RPC ingestion boundary.
- `crates/decode-core`: offline deterministic instruction/error decoding.
- `crates/analyze`: deterministic rule analysis.
- `crates/evidence`: report/evidence schemas.
- `crates/cli`: command-line interface.

## Current Limits

- No historical account-state fetcher yet.
- No replay engine yet.
- No source-code patching or GitHub automation yet.
- Public RPC providers may rate-limit or lack old transaction history.

Use an archival/provider RPC for older transactions.
