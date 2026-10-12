# Team ownership: supervisor architecture

| Owner | Responsibility | Primary files |
| --- | --- | --- |
| Person 1 | Supervisor and support agents; structured handoffs and live adapter | `supervisor.py`, `agent.py`, `model.py` |
| Person 2 | Red-team generation, attack fixtures, and evaluation | `redteam.py`, `attacks.py`, `evaluation.py` |
| Person 3 | Security reviewer, deterministic gateway, regression tests | `reviewer.py`, `defense.py`, `sandbox.py`, `tests/` |
| Person 4 | UI, server integration, exports, presentation | `web/`, `server.py`, `docs/` |

## Shared contracts

- Supervisor assignment: `{task: string}`.
- Support draft: `{to: string, message: string, record_refs: string[]}`.
- Reviewer handoff: `{recommendation: "allow" | "block", findings: string[], evidence: string[]}`.
- Supervisor decision: `{action: "send_draft" | "stop", reason: string}`.
- Support capability: `get_customer({customer_id})`.
- Supervisor capability: `send_reply({to, message})`, always through the gateway.
- Reviewer and red-team roles: no execution capabilities.
- Trusted ticket: `{id, customer_id, sender}` from server data, never ticket content.
- Comparison keys: `baseline`, `reviewed`, `protected`; each run has `handoffs`, `events`, `review`, `supervisor_decision`, `outbox`, `violation`, `task_completed`, `error`.
- Threat model: attacker controls ticket body. All model handoffs are untrusted. Server metadata, role identity, code, and policy are outside attacker control.

## Eight-hour allocation

- Hour 1: agree on message formats, attacker access, and one attack to demonstrate.
- Hours 2–3: normal supervisor workflow and reproducible attack.
- Hours 4–5: reviewer, gateway, three-configuration UI, and integration.
- Hour 6: regressions, failure injection, exports, optional repeated live trials.
- Hours 7–8: fix remaining bugs and rehearse the demo; save results and the model ID.

## Completion criteria

- Three independently isolated configurations use the same ticket.
- Only support reads; only the supervisor requests sends.
- Reviewer failure cannot disable the gateway.
- Post-read review does not hide an earlier unauthorized read in metrics.
- Legitimate plan/renewal tasks continue to succeed.
- Generated candidates are separate from the fixed benchmark.
- API failures remain explicit errors; no simulation fallback.
- Every executed tool action and completed handoff is inspectable and exportable.
