package com.sqlihunter.detection;

import com.sqlihunter.http.BurpHttpClient;

/**
 * A compact fingerprint of a response used for differential comparison:
 * status code, redirect {@code Location} (path only), and normalized body.
 *
 * <p>Comparing these three — not the body alone — is essential for findings
 * whose signal lives in the status/redirect rather than the body. Classic
 * example: a login form where a successful SQL auth-bypass returns
 * {@code 302 -> /bank/main.jsp} (often with a session cookie) while a failed
 * attempt returns {@code 302 -> login.jsp}, both with an empty body.
 */
public final class ResponseFacts {

    private final int statusCode;
    private final String locationPath;
    private final String bodyNorm;
    private final int length;

    private ResponseFacts(int statusCode, String locationPath, String bodyNorm, int length) {
        this.statusCode = statusCode;
        this.locationPath = locationPath;
        this.bodyNorm = bodyNorm;
        this.length = length;
    }

    public static ResponseFacts from(BurpHttpClient.Result r, ResponseNormalizer normalizer, int maxBytes) {
        int status = r.ok() ? r.statusCode() : -1;
        String location = "";
        if (r.ok()) {
            try {
                String loc = r.requestResponse().response().headerValue("Location");
                location = normalizeLocation(loc);
            } catch (RuntimeException ignored) {
                // no Location header
            }
        }
        String body = r.ok() ? r.responseBody() : "";
        if (body.length() > maxBytes) {
            body = body.substring(0, maxBytes);
        }
        return new ResponseFacts(status, location, normalizer.normalize(body), body.length());
    }

    /** Path portion of a Location header, lower-cased, query and trailing slash stripped. */
    static String normalizeLocation(String loc) {
        if (loc == null || loc.isEmpty()) {
            return "";
        }
        String s = loc.trim();
        int scheme = s.indexOf("://");
        if (scheme >= 0) {
            int slash = s.indexOf('/', scheme + 3);
            s = slash >= 0 ? s.substring(slash) : "/";
        }
        int q = s.indexOf('?');
        if (q >= 0) {
            s = s.substring(0, q);
        }
        int h = s.indexOf('#');
        if (h >= 0) {
            s = s.substring(0, h);
        }
        while (s.length() > 1 && s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        return s.toLowerCase();
    }

    public int statusCode() { return statusCode; }
    public String locationPath() { return locationPath; }
    public int length() { return length; }

    /**
     * Whether two responses look "the same" for differential purposes: same
     * status, same redirect target, and body similarity at/above the threshold.
     */
    public boolean similarTo(ResponseFacts other, ResponseNormalizer normalizer, double bodyThreshold) {
        if (this.statusCode != other.statusCode) {
            return false;
        }
        if (!this.locationPath.equals(other.locationPath)) {
            return false;
        }
        double sim = normalizer.similarity(this.bodyNorm, other.bodyNorm);
        return sim >= bodyThreshold;
    }

    public String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append("status=").append(statusCode);
        if (!locationPath.isEmpty()) {
            sb.append(", redirect=").append(locationPath);
        }
        sb.append(", bodyLen=").append(length);
        return sb.toString();
    }
}
