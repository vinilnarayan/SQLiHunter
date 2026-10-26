# HTTP request-generation audit

This document enumerates every code path that can cause SQLiHunter to emit a
network request, demonstrating that **all** of them funnel through Burp's
official Montoya HTTP API.

## The single egress point

All traffic is sent from exactly one line, in one class:

- [`http/BurpHttpClient.java`](../src/main/java/com/sqlihunter/http/BurpHttpClient.java) →
  `api.http().sendRequest(request, options)`

`BurpHttpClient.send(HttpRequest)` is the only method that calls the Montoya
transport. It measures latency, applies a response timeout via
`RequestOptions`, and never throws (transport errors are returned in `Result`).

## Callers (all go through `BurpHttpClient`)

| Caller | Purpose | How it reaches the transport |
|---|---|---|
| `core/ScanEngine` (baseline) | Re-sends the original request to establish a baseline | `Sender` → `client.send(...)` |
| `core/ScanEngine` (`Sender` impl) | Gate applying checkpoint → budget → rate limit | `client.send(...)` |
| `detection/ErrorBasedDetector` | Error probes | `ac.sender().send(...)` |
| `detection/BooleanBlindDetector` | TRUE/FALSE variants | `ac.sender().send(...)` |
| `detection/TimeBasedDetector` | Control + delayed payloads | `ac.sender().send(...)` |

Detectors never hold a `BurpHttpClient` directly; they receive a `Sender`
(implemented by the engine) which enforces cancellation/pause, the request
budget, and the rate limit **before** delegating to `BurpHttpClient.send`.

## Passive path generates no traffic

`detection/PassiveDetector` and the context-menu "passive-scan" action only read
already-captured `HttpRequestResponse` objects. They never create or send
requests.

## Verification

Run from the project root:

```bash
# The only transport call:
grep -rn "sendRequest" src/main/java
#   -> src/main/java/com/sqlihunter/http/BurpHttpClient.java (javadoc + the call)

# No other networking libraries anywhere:
grep -rnE "java\.net\.(URL|Socket|HttpURLConnection)|java\.net\.http|okhttp|apache\.http|HttpClient|new Socket|URLConnection" src/main/java
#   -> (no matches; java.net.URLEncoder/URLDecoder in RequestMutator are
#       string codecs, not network calls)
```

## Behavioural notes (documented, not assumed)

- Extension-generated requests **do not** appear in Proxy history. Proxy history
  records only traffic traversing the Proxy listener. Extension traffic is
  visible in Burp **Logger**.
- Requests inherit Burp's upstream proxy chain and TLS configuration because
  they are dispatched by Burp, not by the extension.
- SQLiHunter does **not** assume Burp session-handling rules or cookie-jar
  refresh are applied automatically to `sendRequest` traffic. It reuses the
  auth headers/cookies present on the selected original request and detects
  authentication loss (repeated 401/403 or login responses) to pause the scan.
