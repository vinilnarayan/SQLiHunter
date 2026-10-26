# Installing SQLiHunter in Burp Suite

## Prerequisites

- Burp Suite **Professional or Community**, recent enough to provide the
  Montoya API (any current release).
- The built JAR: `sqlihunter-1.0.0.jar` (see [build instructions](../README.md#build)).
- Burp's bundled JRE is used to run the extension; no separate Java install is
  needed at runtime. JDK 17+ is only needed to *build*.

## Steps

1. Launch Burp and open/create a project.
2. Go to **Extensions → Installed**.
3. Click **Add**.
4. **Extension type:** `Java`.
5. **Extension file (.jar):** browse to `sqlihunter-1.0.0.jar`.
6. Click **Next**. The output pane should show:
   ```
   SQLiHunter loading... (authorised testing only)
   SQLiHunter loaded. Open the SQLiHunter tab to configure scans. ...
   ```
7. Click **Close**. A new top-level **SQLiHunter** tab appears.

## First run (smoke test)

1. Browse a target through Burp so a request lands in **Proxy → HTTP history**.
2. Right-click the request → **"SQLiHunter: set as scan target"**.
3. The **SQLiHunter → Configuration** tab opens with the target and discovered
   parameters populated, and the target host added to the allow-list.
4. Leave the profile on **Passive only** and click **Start** — this generates no
   traffic and confirms the UI and findings pipeline work.
5. To try active testing against a lab target (e.g. a local OWASP Juice Shop or
   DVWA), switch the profile to **Low active**, confirm the host allow-list, and
   click **Start**, then accept the authorisation dialog.

## Updating

Re-build the JAR, then in **Extensions → Installed** select SQLiHunter and click
**Reload** (or remove and re-add). The extension stops any running scan on
unload.

## Uninstalling

Select SQLiHunter in **Extensions → Installed** and untick/remove it. No files
are written outside the reports you explicitly export.
