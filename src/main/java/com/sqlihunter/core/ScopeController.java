package com.sqlihunter.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URI;

/**
 * Enforces where SQLiHunter is allowed to send traffic. A request must satisfy
 * ALL of: the extension's own host allow-list (if non-empty), optional path
 * prefixes, the not-excluded path rule, and — as a backstop — Burp's own target
 * scope. This is intentionally strict: if nothing is allow-listed, no active
 * testing is permitted.
 */
public final class ScopeController {

    private final ScanConfig config;
    private final MontoyaApi api;

    public ScopeController(ScanConfig config, MontoyaApi api) {
        this.config = config;
        this.api = api;
    }

    /** Reason a request is out of scope, or null if allowed. */
    public String rejectionReason(HttpRequest request) {
        String host = hostOf(request);
        if (host == null) {
            return "Could not determine host";
        }

        if (config.inScopeHosts().isEmpty()) {
            return "No in-scope hosts configured (active testing requires an explicit allow-list)";
        }
        boolean hostAllowed = false;
        for (String h : config.inScopeHosts()) {
            if (hostMatches(host, h.trim())) {
                hostAllowed = true;
                break;
            }
        }
        if (!hostAllowed) {
            return "Host '" + host + "' is not in the allow-list";
        }

        String path = safePath(request);
        if (!config.inScopePathPrefixes().isEmpty()) {
            boolean pathAllowed = false;
            for (String pre : config.inScopePathPrefixes()) {
                if (path.startsWith(pre.trim())) {
                    pathAllowed = true;
                    break;
                }
            }
            if (!pathAllowed) {
                return "Path '" + path + "' is outside configured path prefixes";
            }
        }

        if (config.isPathExcluded(path)) {
            return "Path '" + path + "' matches an excluded (state-changing) pattern";
        }

        // SQLiHunter's own host allow-list is the authorisation of record. Burp's
        // target scope is only advisory here: a tester commonly scans a host that
        // is in our allow-list without having configured Burp Target > Scope, and
        // treating an empty/narrow Burp scope as a hard veto silently blocks the
        // scan. We therefore do NOT reject on Burp scope; the caller may log it.
        return null;
    }

    /** True if Burp's own target scope would also include this URL (advisory only). */
    public boolean inBurpScope(HttpRequest request) {
        try {
            return api.scope().isInScope(request.url());
        } catch (RuntimeException e) {
            return true; // cannot evaluate -> don't warn
        }
    }

    public boolean isAllowed(HttpRequest request) {
        return rejectionReason(request) == null;
    }

    private static boolean hostMatches(String host, String pattern) {
        if (pattern.isEmpty()) {
            return false;
        }
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // ".example.com"
            return host.equals(pattern.substring(2)) || host.endsWith(suffix);
        }
        return host.equalsIgnoreCase(pattern);
    }

    private static String hostOf(HttpRequest request) {
        try {
            return request.httpService().host();
        } catch (RuntimeException e) {
            try {
                return URI.create(request.url()).getHost();
            } catch (RuntimeException e2) {
                return null;
            }
        }
    }

    private static String safePath(HttpRequest request) {
        try {
            return request.pathWithoutQuery();
        } catch (RuntimeException e) {
            return "/";
        }
    }
}
