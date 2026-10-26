# Detection techniques & limitations

## Techniques

### Passive (no traffic)
Scans captured responses for database error signatures across MySQL/MariaDB,
PostgreSQL, MS SQL Server, Oracle, SQLite, and generic JDBC/ORM. A match is
**information disclosure only** — it is capped at **Low** severity / **Low**
confidence and explicitly flagged as requiring active confirmation. A
database-related word on its own never produces a finding; signatures are
specific patterns with per-signature confidence weights.

### Error-based (active)
Injects syntax-breaking probes (`'`, `"`, `')`, `;`, backslash, backtick, …) and
reports a finding **only** when a database error signature appears that was
**absent from the baseline** response. Confidence scales with corroboration:

- strong signature **and** ≥2 distinct triggering probes → High / High
- strong signature **or** ≥2 probes → Medium / Medium
- otherwise → Low / Low

### Boolean-based blind (active)
Sends logically TRUE and FALSE variants and compares full response
**fingerprints — HTTP status + redirect `Location` + normalized body** (not the
body alone). A finding requires, consistently across the configured number of
confirmations:

- repeated TRUE responses are stable (similar to each other), **and**
- repeated FALSE responses are stable, **and**
- TRUE and FALSE **diverge** from each other.

This divergence-plus-stability model (rather than "TRUE must match the captured
baseline") is deliberate so that **authentication-bypass** cases are caught: on a
login form the captured request is usually a *failed* attempt, and a successful
SQL bypass flips the status/redirect (e.g. `302 → /bank/main.jsp` vs
`302 → login.jsp`) while leaving the body empty. Bodies are normalized (CSRF
tokens, nonces, timestamps, long opaque ids, whitespace stripped) so dynamic
noise does not read as a difference. Payloads include comment-terminated `AND`
pairs (`… ' AND '1'='1' -- ` / `… ' AND '1'='2' -- `) which bypass a password
check for a valid identifier, plus `OR` and plain in-context pairs. Result:
**Medium** severity, **High** confidence (2+ confirmations).

> **Capture a clean request.** Set the scan target from a *normal* request, not
> one that already contains a working payload. If the captured value already ends
> the statement or comments it out (e.g. `uid=admin'--`), every injected probe is
> neutralised and TRUE/FALSE collapse to identical responses — nothing is found.

### Time-based blind (active, opt-in, OFF by default)
Establishes a control latency, injects a single bounded delay payload, and
**re-measures** a candidate before reporting. Always reported as **suspected**
(never High/Confirmed) because timing is noisy. Strict per-parameter probe caps
and a conservative delay apply.

### Database fingerprinting
Derived from error evidence only; never issues invasive version queries. Returns
`Unknown` when evidence is weak or families conflict.

## Confidence & severity model

| Confidence | Meaning |
|---|---|
| Potential | Weak/passive indicator; needs active confirmation. |
| Low | Single weak active indicator. |
| Medium | Credible, corroborated indicator. |
| High | Strongly corroborated (e.g. multi-probe error, repeated boolean). |
| Confirmed | **Manual only** — set by the tester after verification. |

| Severity | Guidance |
|---|---|
| Informational | Fingerprinting / suspicious behaviour, no demonstrated injection. |
| Low | Limited disclosure or weak evidence. |
| Medium | Credible injection, impact not fully established. |
| High | Strongly supported injection with significant impact. |
| Critical | **Never automatic** — reserved for demonstrated severe compromise. |

CVSS v4.0 vectors are attached only where the evidence supports them (error-
based High and boolean-based findings carry illustrative vectors); treat vectors
as starting points and adjust for the real environment.

## False-positive handling (by design)

- Baseline diffing (error-based ignores errors already present in baseline).
- Response normalization + repeated confirmation (boolean).
- Control vs. re-measured delay (time-based).
- Specific, weighted signatures (no generic keyword matching).
- Deduplication by endpoint + parameter + detection type.

Negative unit tests assert that benign DB vocabulary, dynamic tokens/timestamps,
and ambiguous evidence do **not** produce confirmed findings.

## Known limitations

- **Duplicate same-name parameters**: Montoya's `withUpdatedParameters` updates
  all occurrences of a (name, type) together. SQLiHunter warns when duplicates
  are present. For precise single-occurrence testing, use Repeater manually.
- **XML / multipart**: supported best-effort via Montoya parameter types; deeply
  nested XML or complex multipart may need manual testing. SQLiHunter reports
  bodies it cannot parse as skipped rather than guessing.
- **JSON**: nested objects/arrays supported via JSON-pointer mutation; values
  are written through Gson (payloads appear literally, not HTML-escaped).
- **Burp edition**: all detection here uses core Montoya HTTP APIs available in
  Community and Professional. The extension does not require Pro-only Scanner
  APIs; integrating findings into Burp's Scanner issue list is a Pro-only
  enhancement not required for operation.
- **Proxy history**: extension traffic does not appear there (see
  [HTTP_REQUEST_PATHS.md](HTTP_REQUEST_PATHS.md)); use Burp Logger.

## Authentication

SQLiHunter reuses the selected request's auth headers/cookies and preserves
CSRF-related components as sent. It never authenticates, changes credentials, or
mutates account state. It cannot guarantee browser-side behaviours (JS-set
headers, token refresh) are reproduced; where a session expires it detects the
condition and pauses. Re-authenticate (in the browser/Burp) and Resume.
