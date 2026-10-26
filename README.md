# SQLiHunter

A Burp Suite extension for detecting SQL injection (SQLi) in web applications,
APIs, and other HTTP services. Built on the official **Montoya API**.

> **Authorised use only.** SQLiHunter is for penetration testing and security
> assessments you are explicitly authorised to perform. Active testing is **off
> by default** and requires an explicit in-scope host allow-list.

---

## Key design guarantee: all traffic goes through Burp

Every HTTP request the extension sends is dispatched through Burp's official
Montoya transport — `api.http().sendRequest(...)` — from a single class,
[`BurpHttpClient`](src/main/java/com/sqlihunter/http/BurpHttpClient.java). No
`java.net.http`, OkHttp, Apache HttpClient, raw sockets, or any other networking
library is used anywhere. See
[docs/HTTP_REQUEST_PATHS.md](docs/HTTP_REQUEST_PATHS.md) for the full audit.

Because requests go through Burp, they use Burp's configured upstream proxy and
TLS handling. **Extension-generated requests do not automatically appear in
Proxy history** (Proxy history only records traffic through the Proxy listener).
They are visible in Burp's **Logger**, and the extension logs a per-scan summary
to the **Extensions → Output** log.

---

## Features

- **Passive detection** — scans captured requests/responses for database error
  signatures (MySQL/MariaDB, PostgreSQL, MS SQL Server, Oracle, SQLite, generic
  JDBC/ORM) with confidence weighting. Generates no traffic.
- **Active detection** (opt-in):
  - **Error-based** — injects syntax-breaking probes; reports only signatures
    absent from the baseline.
  - **Boolean-based blind** — normalized, repeated TRUE/FALSE differential.
  - **Time-based blind** — conservative, disabled by default, reported as
    *suspected* only.
- **Database fingerprinting** from error evidence (`Unknown` when inconclusive).
- **Request mutation engine** for URL, form body, cookies, nested JSON, XML,
  multipart fields, headers, and path segments — preserving encoding and
  unrelated data.
- **Scope & safety controls** — host allow-list, path prefixes, excluded
  parameters/paths, request budget, concurrency cap, rate limit, scan timeout,
  pause/resume/stop, and a confirmation dialog before active testing.
- **False-positive reduction** — multi-indicator confidence scoring; findings
  are classified Potential / Low / Medium / High (and a manual *Confirmed*).
- **Reporting** — JSON, CSV, and a self-contained HTML report, with optional
  redaction of secrets. Findings map to **OWASP Top 10:2021 A03 Injection**.

---

## Requirements

- **Burp Suite** Professional or Community Edition (Montoya API).
- **JDK 17+** to build.

The extension itself loads in both editions. Features that depend on Pro-only
APIs degrade gracefully; see [docs/DETECTION_AND_LIMITATIONS.md](docs/DETECTION_AND_LIMITATIONS.md).

---

## Build

### With Gradle (recommended)

```bash
gradle shadowJar
# or, if you have the wrapper jar: ./gradlew shadowJar
```

Output: `build/libs/sqlihunter-1.0.0.jar` (Gson bundled and relocated; Montoya
excluded because Burp provides it).

Dependencies (declared in [`build.gradle`](build.gradle)):

| Dependency | Version | Scope |
|---|---|---|
| `net.portswigger.burp.extensions:montoya-api` | 2025.12 | compileOnly |
| `com.google.code.gson:gson` | 2.11.0 | bundled |
| `org.junit.jupiter:junit-jupiter` | 5.10.2 | test |

### Without Gradle

If Gradle is not installed, a self-contained script reproduces the same build
with `javac` (JDK 17+ and internet access to Maven Central required):

```bash
./build-nogradle.sh
```

Output: `build/sqlihunter-1.0.0.jar`.

### Run tests

```bash
gradle test
```

(40 unit tests covering mutation/encoding, JSON, normalization, signatures,
fingerprinting, redaction, scope enforcement, budget, rate limiting, and
reporting — including negative/false-positive cases.)

---

## Install in Burp

1. **Extensions → Installed → Add**.
2. Extension type: **Java**.
3. Select the built JAR (`sqlihunter-1.0.0.jar`).
4. Confirm `SQLiHunter loaded` in **Extensions → Output**. A **SQLiHunter** tab
   appears in the main window.

Full steps and screenshots guidance: [docs/INSTALL.md](docs/INSTALL.md).

---

## Usage

1. In Proxy history / Repeater / Logger, right-click a request →
   **"SQLiHunter: set as scan target"** (or **"passive-scan selected item(s)"**).
2. Open the **SQLiHunter** tab → **Configuration**:
   - Review discovered parameters (select a subset, or leave none selected to
     test all eligible).
   - Choose a **profile** (Passive only / Low active / Standard active / Custom)
     and techniques.
   - Add in-scope hosts to the **allow-list** (required for active testing).
   - Set budgets, rate, and timeouts.
3. Click **Start**. For active scans, confirm the authorisation dialog.
4. Watch **Progress**; review results in **Findings**; export from there.
5. **Manual confirmation:** select a finding and use the **"Send to Repeater"**
   buttons at the bottom of the detail view. Each request variant opens in its
   own Repeater tab — for boolean-blind findings that means **Baseline**, **TRUE
   variant**, and **FALSE variant** as three separate tabs to replay and compare
   by hand. "Send all to Repeater" pushes every variant at once.

Configuration reference: [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

---

## Sample output

See [`samples/`](samples/): `sample-report.json`, `sample-report.csv`,
`sample-report.html` (generated by the reporters, with redaction enabled).

---

## Project layout

```
src/main/java/com/sqlihunter/
  SQLiHunterExtension.java      Entry point (implements BurpExtension)
  http/BurpHttpClient.java      SINGLE network egress (api.http().sendRequest)
  core/                         Config, scope, rate limiter, budget, engine
  mutation/                     Parameter discovery & safe request mutation
  detection/                    Passive + error/boolean/time detectors, signatures
  findings/                     Finding model, store (thread-safe, dedup)
  report/                       JSON/CSV/HTML reporters + redactor
  ui/                           SQLiHunter tab, config/progress/findings panels
docs/                           Install, configuration, limitations, troubleshooting,
                                HTTP-API audit, security review checklist
samples/                        Example reports
```

---

## Safety & limitations

SQLiHunter uses **non-destructive** test cases only: it never runs
DROP/DELETE/UPDATE/INSERT, stacked queries for data change, UNION-based
extraction, file access, or administrative procedures. It will not auto-follow
links or expand to third-party hosts.

Automated findings are evidence-backed but still require manual validation
before external reporting. `CRITICAL` severity and `Confirmed` confidence are
never assigned automatically. Read
[docs/DETECTION_AND_LIMITATIONS.md](docs/DETECTION_AND_LIMITATIONS.md) before
relying on results.
