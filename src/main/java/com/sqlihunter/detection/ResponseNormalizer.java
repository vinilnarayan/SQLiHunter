package com.sqlihunter.detection;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Normalises response bodies so that boolean-based differential comparisons are
 * robust against noise (CSRF tokens, timestamps, counters, nonces, ads, random
 * ids). Also provides a similarity ratio used by the boolean-blind detector.
 *
 * <p>Application-specific rules can be added as extra regex replacements; the
 * defaults strip the most common dynamic tokens.
 */
public final class ResponseNormalizer {

    private final List<Pattern> stripPatterns = new ArrayList<>();

    public ResponseNormalizer() {
        addDefaults();
    }

    private void addDefaults() {
        // CSRF / auth tokens embedded in HTML or JSON.
        strip("(?i)(csrf[-_]?token|authenticity_token|__RequestVerificationToken)[\"'=:\\s]+[\\w\\-+/=.]+");
        strip("(?i)(nonce|state|request_id|trace[-_]?id|session[-_]?id)[\"'=:\\s]+[\\w\\-+/=.]+");
        // ISO timestamps and common date formats.
        strip("\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+\\-]\\d{2}:?\\d{2})?");
        strip("\\d{2}/\\d{2}/\\d{4}");
        // Epoch-like long integers (timers, cache-busters).
        strip("\\b\\d{10,13}\\b");
        // Hex blobs (etags, ids).
        strip("\\b[0-9a-fA-F]{16,}\\b");
        // Long opaque quoted tokens (e.g. value="aZ9-_..."), common for nonces/ids.
        strip("\"[A-Za-z0-9+/=_\\-]{12,}\"");
        // Long unquoted opaque tokens.
        strip("\\b[A-Za-z0-9+/=_\\-]{24,}\\b");
        // Collapse whitespace last.
    }

    /** Add a custom strip rule (application-specific normalization). */
    public void strip(String regex) {
        stripPatterns.add(Pattern.compile(regex));
    }

    public String normalize(String body) {
        if (body == null) {
            return "";
        }
        String out = body;
        for (Pattern p : stripPatterns) {
            out = p.matcher(out).replaceAll("");
        }
        // Collapse all whitespace runs to a single space.
        out = out.replaceAll("\\s+", " ").trim();
        return out;
    }

    /**
     * Similarity ratio in [0,1] between two bodies after normalization, using a
     * token (shingle) Jaccard-style measure that is stable for large bodies.
     */
    public double similarity(String a, String b) {
        String na = normalize(a);
        String nb = normalize(b);
        if (na.isEmpty() && nb.isEmpty()) {
            return 1.0;
        }
        java.util.Set<String> ta = tokens(na);
        java.util.Set<String> tb = tokens(nb);
        if (ta.isEmpty() && tb.isEmpty()) {
            return 1.0;
        }
        java.util.Set<String> inter = new java.util.HashSet<>(ta);
        inter.retainAll(tb);
        java.util.Set<String> union = new java.util.HashSet<>(ta);
        union.addAll(tb);
        return union.isEmpty() ? 1.0 : (double) inter.size() / union.size();
    }

    private java.util.Set<String> tokens(String s) {
        java.util.Set<String> set = new java.util.HashSet<>();
        String[] words = s.split("[^\\p{Alnum}]+");
        for (String w : words) {
            if (!w.isEmpty()) {
                set.add(w.toLowerCase());
            }
        }
        return set;
    }
}
