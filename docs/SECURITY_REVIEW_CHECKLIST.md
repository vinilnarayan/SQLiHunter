# SQLiHunter security review checklist

A self-review checklist for the extension itself (not the targets it tests).

## Transport & network behaviour
- [x] All requests sent via `api.http().sendRequest(...)` only
      (single class `BurpHttpClient`; see HTTP_REQUEST_PATHS.md).
- [x] No third-party HTTP libraries, sockets, or `java.net.http` used.
- [x] Per-request response timeout set via `RequestOptions`.
- [x] No auto-following of links or expansion to third-party hosts.
- [x] Accurate documentation that extension traffic is not in Proxy history.

## Scope & authorisation
- [x] Active testing requires an explicit in-scope host allow-list.
- [x] Burp target scope honoured as a backstop.
- [x] State-changing endpoints excluded by default (logout/payment/delete/…).
- [x] Confirmation dialog before any active testing.
- [x] Active testing disabled by default; time-based disabled by default.

## Safety of test payloads
- [x] Non-destructive payloads only (no DROP/DELETE/UPDATE/INSERT, no stacked
      data-changing queries, no UNION extraction, no file/OS access, no admin
      procedures).
- [x] Sensitive parameters (password, token, otp, csrf, …) excluded by default.
- [x] Request budget, concurrency cap, rate limit, and scan timeout enforced.
- [x] Cancellation and pause/resume are cooperative and prompt.

## Secrets handling
- [x] Authorization/Cookie/Set-Cookie and token-like fields redacted in exported
      reports (default on).
- [x] No plaintext logging of auth headers, cookies, tokens, or secrets.
- [x] Live UI shows evidence to the tester but exports can be redacted.

## Robustness & reliability
- [x] Detector exceptions are caught per-parameter; Burp never crashes.
- [x] Transport failures captured, not thrown.
- [x] Thread-safe findings store with deduplication.
- [x] Response size cap guards local memory.
- [x] Bounded worker pool; daemon threads; clean shutdown on unload.
- [x] Malformed/unparseable inputs reported as skipped, not silently mutated.

## Input handling / encoding
- [x] URL/body values URL-encoded; path segments percent-encoded.
- [x] Header values stripped of CR/LF (no header injection via payloads).
- [x] JSON mutated via a real parser (Gson), preserving structure.
- [x] XML values escaped.
- [x] Malformed percent-encoding tolerated without corrupting the request.

## Privacy
- [x] No data sent anywhere except the user-selected target via Burp.
- [x] Reports written only to a path the tester chooses.
- [x] No telemetry, no external calls.

## Build integrity
- [x] Montoya is `compileOnly` (provided by Burp), not bundled.
- [x] Gson bundled and relocated (Gradle build) to avoid classloader clashes.
- [x] Pinned dependency versions documented.

## Residual risks / operator responsibilities
- [ ] Operator confirms written authorisation for every target.
- [ ] Operator validates findings before external reporting.
- [ ] Operator reviews excluded-path/param lists for the specific app.
- [ ] Operator sets budgets/rate appropriate to the target's capacity.
