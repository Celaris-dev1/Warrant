# Pricing

Warrant is open core. Token mint/verify, the PEP (`warrantd`), delegation/attenuation,
revocation, blast-radius, receipts, `warrantd gateway` (MCP/A2A protocol gateway, PoP,
routing, authorize/deny, batching), and the Go/Python/MCP/A2A/OpenAI/LangChain adapters are
free, forever, with no license required. See the README's "Built vs roadmap" and LICENSING
sections for exactly what that covers.

One *gateway* feature on top of `warrantd gateway` requires a paid, offline license key.
Nothing is ever deleted or hidden when a license lapses or was never installed: that feature
just turns off (or, briefly, keeps working with a warning — see "Grace period" below) until
a valid license is present again.

## Community — free

- `warrantd` broker + PEP: workload registration, token mint/delegate, approvals, authorize,
  revoke, blast-radius
- `warrantd gateway`: the MCP/A2A protocol gateway, PoP verification, request routing,
  authorize/deny, batching
- Go and Python SDKs, the MCP/A2A/OpenAI/LangChain adapters

## Enterprise — contact sales

Unlocks, on top of Community:

- **Gateway tools/list filtering.** `WARRANT_GATEWAY_FILTER_TOOLS_LIST=true` filters an MCP
  `tools/list` response down to only the tools the presented credential's scopes permit, so
  a downstream LLM/agent never even sees tools it cannot call.

Custom seat counts, multi-year terms, and support SLAs — contact sales.

## How licensing works

A license is a small JSON document (customer, edition, features, seats, issued/expiry
dates) signed with Ed25519 and handed to you as one base64url token. Set it via
`WARRANT_LICENSE` (the token itself) or `WARRANT_LICENSE_FILE` (a path to a file holding
it). Verification is entirely offline: the token is checked against a vendor public key
compiled into the `warrantd` binary. There is no phone-home, no activation server, and no
telemetry — this works in air-gapped environments.

- `warrantd license show` — current state, customer, edition, features, seats, expiry.
- `warrantd license verify <token|file>` — verify a token offline and print what it grants.

**Grace period.** A license that has expired keeps unlocking its feature, with a loud
warning, for 14 days — so a delayed renewal doesn't interrupt anyone's workflow. After that
it reads as expired and the feature turns off (Community features are unaffected).

**Tampered or invalid tokens** are treated exactly like no license at all (Community), with
a warning logged — Warrant fails safe, never open, on a bad token, but it never fails your
build over one either.

See the README's LICENSING section for how a vendor issues keys with `tools/licensegen`.
