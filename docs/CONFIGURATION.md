# Configuration reference

All options live on the **SQLiHunter → Configuration** tab. Safety-relevant
defaults are conservative.

## 1. Target & parameters

- **Target** — set via right-click → *"SQLiHunter: set as scan target"*.
- **Parameter list** — discovered automatically. Select a subset to test, or
  leave the selection empty to test **all eligible** parameters.
- **Re-discover parameters** — re-parses after you toggle Header/Path testing.

## 2. Profile & techniques

| Profile | Active | Error | Boolean | Time | Budget | Rate |
|---|---|---|---|---|---|---|
| Passive only | off | – | – | – | – | – |
| Low active | on | on | off | off | 60 | 3/s |
| Standard active | on | on | on | off | 300 | 5/s |
| Custom | as set | as set | as set | as set | as set | as set |

Techniques can be toggled individually in **Custom**. Time-based is always
opt-in, even in Standard.

## 3. Parameter locations

URL, Body (form), JSON, Cookies, XML, Headers, Path. URL/Body/JSON are on by
default; Cookies/XML/Headers/Path are off (more intrusive or noisier).

## 4. Scope & exclusions (one entry per line)

- **In-scope hosts (allow-list)** — **required** for active testing. Supports
  exact hosts and `*.example.com` wildcards. Active testing also respects Burp's
  own target scope as a backstop.
- **In-scope path prefixes** — optional; if set, only matching paths are tested.
- **Excluded parameter names** — default includes `csrf`, `password`, `token`,
  `otp`, etc. Matched as case-insensitive substrings.
- **Excluded path substrings** — default includes `logout`, `payment`,
  `checkout`, `delete`, `transfer`, `deactivate`, etc., to avoid state-changing
  endpoints.

## 5. Budgets, rate & safety limits

| Setting | Default | Meaning |
|---|---|---|
| Max requests | 300 | Hard cap per scan (budget). Scan stops when reached. |
| Max concurrency | 4 | Worker threads sending in parallel. |
| Requests / second | 5.0 | Global throttle across all workers. |
| Scan timeout (s) | 600 | Watchdog cancels the scan at this wall-clock limit. |
| Response timeout (ms) | 15000 | Per-request timeout via Montoya `RequestOptions`. |
| Max response bytes | 2,000,000 | Response text considered for analysis (guards memory). |
| Time-based delay (s) | 5 | Delay injected by time-based payloads (1–30). |
| Boolean confirmations | 2 | Times a boolean differential must repeat consistently. |
| Redact secrets in reports | on | Masks auth/cookies/tokens in exported files. |

## Controls

- **Start** — validates target/scope; for active scans shows an authorisation
  confirmation dialog summarising target, parameter count, budget, rate, and
  techniques.
- **Pause / Resume** — cooperative; workers stop at the next checkpoint.
- **Stop** — cancels and shuts down workers.

## Authentication handling

SQLiHunter reuses the auth headers and cookies on the selected request. It does
**not** log in, change passwords, or alter account state. If it sees repeated
`401`/`403` or login/"session expired" responses, it **pauses** the scan and
logs a message so you can re-authenticate and resume. See
[DETECTION_AND_LIMITATIONS.md](DETECTION_AND_LIMITATIONS.md#authentication).
