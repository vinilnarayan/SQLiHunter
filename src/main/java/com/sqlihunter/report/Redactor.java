package com.sqlihunter.report;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Redacts secrets from evidence text before it is written to a saved report.
 * Authorization headers, cookies, set-cookie, and common token fields are
 * replaced with a placeholder. The live UI shows un-redacted evidence; only
 * exported artifacts are scrubbed (controlled by ScanConfig.redactReports).
 */
public final class Redactor {

    private static final String MASK = "***REDACTED***";

    private static final Pattern[] HEADER_LINES = {
            Pattern.compile("(?im)^(Authorization:\\s*).*$"),
            Pattern.compile("(?im)^(Proxy-Authorization:\\s*).*$"),
            Pattern.compile("(?im)^(Cookie:\\s*).*$"),
            Pattern.compile("(?im)^(Set-Cookie:\\s*).*$"),
            Pattern.compile("(?im)^(X-Api-Key:\\s*).*$"),
            Pattern.compile("(?im)^(X-Auth-Token:\\s*).*$"),
    };

    // token-ish key/value pairs inside bodies or query strings
    private static final Pattern TOKEN_KV = Pattern.compile(
            "(?i)(\"?(?:password|passwd|pwd|token|access_token|refresh_token|secret|api[_-]?key|session[_-]?id|otp)\"?\\s*[:=]\\s*\"?)([^\"&\\s,}]+)");

    private final boolean enabled;

    public Redactor(boolean enabled) {
        this.enabled = enabled;
    }

    public String apply(String text) {
        if (!enabled || text == null || text.isEmpty()) {
            return text == null ? "" : text;
        }
        String out = text;
        for (Pattern p : HEADER_LINES) {
            out = p.matcher(out).replaceAll("$1" + Matcher.quoteReplacement(MASK));
        }
        out = TOKEN_KV.matcher(out).replaceAll("$1" + Matcher.quoteReplacement(MASK));
        return out;
    }
}
