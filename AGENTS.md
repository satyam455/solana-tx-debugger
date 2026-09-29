# Solana Debugger Engineering Rules

- Never add transaction signing or `sendTransaction`.
- `trace`, `decode-*`, `analyze`, and `evidence` may not perform network IO.
- LLM output is never passed directly to a shell.
- Every diagnosis must cite evidence IDs.
- Replay verification is authoritative over LLM confidence.
- Unknown programs must degrade gracefully.
- Support legacy, v0, and v1 transactions in the trace schema.
- No test may access mainnet unless explicitly tagged `live-rpc-tests`.
- Run fmt, clippy, and relevant tests before completing a task.

