# Troubleshooting

## Build

**`gradle: command not found`**
Use the no-Gradle script: `./build-nogradle.sh` (needs JDK 17+ and internet
access to Maven Central). Or install Gradle 8.x (`brew install gradle`,
`sdk install gradle`).

**Compilation fails with Montoya symbol errors**
Ensure the Montoya version in `build.gradle` matches a version on Maven Central
(default `2025.12`). The API is `compileOnly`; do not bundle it.

**Shadow plugin not found**
The build uses `com.gradleup.shadow`. With network access Gradle resolves it
from the Gradle Plugin Portal. Offline, use `./build-nogradle.sh`.

## Loading in Burp

**Extension fails to load / `NoClassDefFoundError: com.google.gson...`**
You loaded a JAR that does not bundle Gson. Build with `gradle shadowJar` or
`./build-nogradle.sh` (both bundle Gson). Do not load `build/classes` directly.

**`UnsupportedClassVersionError`**
Your Burp JRE is older than the bytecode. Build targets Java 17; use a current
Burp release (its bundled JRE is 17+).

**No SQLiHunter tab appears**
Check **Extensions → Output** and **Errors** for a stack trace. The tab is
registered on the Swing EDT; if Burp reports an init error, capture the trace.

## Scanning

**"Active scan did not start"**
Active testing requires a non-empty in-scope host allow-list and the target must
be in Burp's scope. Add the host under **Scope & exclusions** and check the
output log for the exact rejection reason.

**No requests are being sent**
Confirm the profile is not **Passive only** and that at least one technique and
one parameter location are enabled. Check the request budget is not already 0.

**Scan paused unexpectedly**
SQLiHunter detected possible authentication loss (repeated 401/403 or login
responses). Re-authenticate and click **Resume**, or **Stop**.

**Too many/false findings**
Raise **Boolean confirmations**, keep normalization defaults, disable
time-based, and prefer **Low active**. Review the per-finding evidence and
limitations before reporting.

**Requests don't show in Proxy history**
Expected — extension traffic is not Proxy traffic. Use Burp **Logger** to see
it.

## Performance

**Burp becomes sluggish during a scan**
Lower **Max concurrency** and **Requests/second**, and/or reduce **Max response
bytes**. The engine is bounded by design; these three settings control load.

**Scan never ends**
The watchdog cancels at **Scan timeout (s)**. Lower it, or click **Stop**.
