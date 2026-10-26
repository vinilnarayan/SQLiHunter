package com.sqlihunter.core;

import com.sqlihunter.config.ScanConfigView;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Mutable, thread-safe scan configuration shared between the UI and the engine.
 * Safety-relevant defaults are conservative: active testing off, time-based off,
 * small budgets, low rate.
 */
public final class ScanConfig implements ScanConfigView {

    // ---- profile & techniques ----
    private volatile ScanProfile profile = ScanProfile.PASSIVE_ONLY;
    private volatile boolean passiveEnabled = true;
    private volatile boolean activeEnabled = false;
    private volatile boolean errorBasedEnabled = true;
    private volatile boolean booleanBlindEnabled = true;
    private volatile boolean timeBasedEnabled = false;      // OFF by default (requirement)
    private volatile boolean fingerprintingEnabled = true;

    // ---- location toggles ----
    private volatile boolean testUrl = true;
    private volatile boolean testBody = true;
    private volatile boolean testCookies = false;
    private volatile boolean testJson = true;
    private volatile boolean testXml = false;
    private volatile boolean testHeaders = false;
    private volatile boolean testPath = false;

    // ---- scope ----
    private final List<String> inScopeHosts = new CopyOnWriteArrayList<>();
    private final List<String> inScopePathPrefixes = new CopyOnWriteArrayList<>();
    private final List<String> excludedParamNames =
            new CopyOnWriteArrayList<>(Arrays.asList("csrf", "csrftoken", "authenticity_token",
                    "__requestverificationtoken", "password", "passwd", "otp", "mfa", "token"));
    private final List<String> excludedPathSubstrings =
            new CopyOnWriteArrayList<>(Arrays.asList("logout", "signout", "delete", "payment",
                    "checkout", "purchase", "transfer", "account/close", "deactivate"));

    // ---- budgets & limits ----
    private volatile int maxRequests = 300;
    private volatile int maxConcurrency = 4;
    private volatile double requestsPerSecond = 5.0;
    private volatile int scanTimeoutSeconds = 600;
    private volatile long responseTimeoutMillis = 15_000L;
    private volatile int maxResponseBytes = 2_000_000; // guard local memory

    // ---- time-based safety ----
    private volatile int timeBasedDelaySeconds = 5;
    private volatile int timeBasedMaxProbesPerParam = 3;

    // ---- boolean-blind tuning ----
    private volatile double booleanTrueSimilarityThreshold = 0.95;   // true ~= baseline
    private volatile double booleanFalseDivergenceThreshold = 0.90;  // false clearly differs
    private volatile int booleanConfirmations = 2;                   // repeat for consistency

    // ---- reporting ----
    private volatile boolean redactReports = true;

    public void applyProfile(ScanProfile p) {
        this.profile = p;
        switch (p) {
            case PASSIVE_ONLY:
                activeEnabled = false;
                timeBasedEnabled = false;
                break;
            case LOW_ACTIVE:
                activeEnabled = true;
                errorBasedEnabled = true;
                booleanBlindEnabled = false;
                timeBasedEnabled = false;
                maxRequests = 60;
                requestsPerSecond = 3.0;
                maxConcurrency = 2;
                break;
            case STANDARD_ACTIVE:
                activeEnabled = true;
                errorBasedEnabled = true;
                booleanBlindEnabled = true;
                timeBasedEnabled = false; // still opt-in only
                maxRequests = 300;
                requestsPerSecond = 5.0;
                maxConcurrency = 4;
                break;
            case CUSTOM:
            default:
                // leave current values untouched
                break;
        }
    }

    public boolean isParamExcluded(String name) {
        if (name == null) {
            return false;
        }
        String lower = name.toLowerCase();
        for (String ex : excludedParamNames) {
            if (lower.equals(ex.toLowerCase()) || lower.contains(ex.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    public boolean isPathExcluded(String path) {
        if (path == null) {
            return false;
        }
        String lower = path.toLowerCase();
        for (String ex : excludedPathSubstrings) {
            if (lower.contains(ex.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    // ---- getters/setters (thread-safe via volatile) ----
    public ScanProfile profile() { return profile; }

    public boolean passiveEnabled() { return passiveEnabled; }
    public void setPassiveEnabled(boolean v) { this.passiveEnabled = v; }

    public boolean activeEnabled() { return activeEnabled; }
    public void setActiveEnabled(boolean v) { this.activeEnabled = v; }

    public boolean errorBasedEnabled() { return errorBasedEnabled; }
    public void setErrorBasedEnabled(boolean v) { this.errorBasedEnabled = v; }

    public boolean booleanBlindEnabled() { return booleanBlindEnabled; }
    public void setBooleanBlindEnabled(boolean v) { this.booleanBlindEnabled = v; }

    public boolean timeBasedEnabled() { return timeBasedEnabled; }
    public void setTimeBasedEnabled(boolean v) { this.timeBasedEnabled = v; }

    public boolean fingerprintingEnabled() { return fingerprintingEnabled; }
    public void setFingerprintingEnabled(boolean v) { this.fingerprintingEnabled = v; }

    public boolean testUrl() { return testUrl; }
    public void setTestUrl(boolean v) { this.testUrl = v; }
    public boolean testBody() { return testBody; }
    public void setTestBody(boolean v) { this.testBody = v; }
    public boolean testCookies() { return testCookies; }
    public void setTestCookies(boolean v) { this.testCookies = v; }
    public boolean testJson() { return testJson; }
    public void setTestJson(boolean v) { this.testJson = v; }
    public boolean testXml() { return testXml; }
    public void setTestXml(boolean v) { this.testXml = v; }
    public boolean testHeaders() { return testHeaders; }
    public void setTestHeaders(boolean v) { this.testHeaders = v; }
    public boolean testPath() { return testPath; }
    public void setTestPath(boolean v) { this.testPath = v; }

    public List<String> inScopeHosts() { return inScopeHosts; }
    public List<String> inScopePathPrefixes() { return inScopePathPrefixes; }
    public List<String> excludedParamNames() { return excludedParamNames; }
    public List<String> excludedPathSubstrings() { return excludedPathSubstrings; }

    public int maxRequests() { return maxRequests; }
    public void setMaxRequests(int v) { this.maxRequests = Math.max(1, v); }
    public int maxConcurrency() { return maxConcurrency; }
    public void setMaxConcurrency(int v) { this.maxConcurrency = Math.max(1, v); }
    public double requestsPerSecond() { return requestsPerSecond; }
    public void setRequestsPerSecond(double v) { this.requestsPerSecond = Math.max(0.1, v); }
    public int scanTimeoutSeconds() { return scanTimeoutSeconds; }
    public void setScanTimeoutSeconds(int v) { this.scanTimeoutSeconds = Math.max(1, v); }
    public long responseTimeoutMillis() { return responseTimeoutMillis; }
    public void setResponseTimeoutMillis(long v) { this.responseTimeoutMillis = Math.max(1000, v); }
    public int maxResponseBytes() { return maxResponseBytes; }
    public void setMaxResponseBytes(int v) { this.maxResponseBytes = Math.max(10_000, v); }

    public int timeBasedDelaySeconds() { return timeBasedDelaySeconds; }
    public void setTimeBasedDelaySeconds(int v) { this.timeBasedDelaySeconds = Math.max(1, Math.min(30, v)); }
    public int timeBasedMaxProbesPerParam() { return timeBasedMaxProbesPerParam; }
    public void setTimeBasedMaxProbesPerParam(int v) { this.timeBasedMaxProbesPerParam = Math.max(1, Math.min(10, v)); }

    public double booleanTrueSimilarityThreshold() { return booleanTrueSimilarityThreshold; }
    public double booleanFalseDivergenceThreshold() { return booleanFalseDivergenceThreshold; }
    public int booleanConfirmations() { return booleanConfirmations; }
    public void setBooleanConfirmations(int v) { this.booleanConfirmations = Math.max(1, Math.min(5, v)); }

    public boolean redactReports() { return redactReports; }
    public void setRedactReports(boolean v) { this.redactReports = v; }

    public List<String> enabledHeaderNames() {
        // Default header set offered when header testing is enabled.
        return new ArrayList<>(Arrays.asList("User-Agent", "Referer", "X-Forwarded-For"));
    }
}
