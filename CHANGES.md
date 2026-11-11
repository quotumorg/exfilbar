## 0.5.5

- Literal fd redirects and output to /dev/null preserve recognized upload sources, destinations and route checks; file-writing redirects remain unresolved.
- Newly recorded decisions use an append-only SHA-256 chain anchored to a random install id, with optional local HMAC and legacy-ledger migration.
- `/exfil verify` and `python3 -m exfilbar verify --data-dir <directory>` check history offline and report the first broken index or preceding unverified legacy records.
- Feed status can show a small integrity result after explicit verification; changes invalidate it without adding work to polling.
- HMAC also authenticates the current head against adjusted suffix truncation; unsafe existing key files fail closed.
- Timing property tests use an injected admission clock, with separate real elapsed checks and deterministic production-deadline regressions.
- Unattended behavior is documented and tested: denials return block, never approval escalation.
- The attack rehearsal now isolates registration storage too, without consulting a Hermes profile.

## 0.5.4

Connection-qualified Desktop reads, owner mismatch and stale-response guards, HTTPie multipart routing, cold-glob budgets and an isolated registered-hook route demo; read-only polling, bounded concurrent writer queues and retrying temporary-unavailable states.
