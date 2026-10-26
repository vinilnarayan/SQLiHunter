package com.sqlihunter.detection;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Formats request/response text for inclusion in findings. Bodies are truncated
 * to a sane size so evidence never bloats memory or reports. Redaction of
 * secrets is applied separately at export time by {@code report.Redactor}.
 */
public final class Evidence {

    private static final int MAX_BODY = 4000;

    private Evidence() {
    }

    public static String requestText(HttpRequest req) {
        if (req == null) {
            return "";
        }
        try {
            return truncate(req.toString());
        } catch (RuntimeException e) {
            return "<unavailable>";
        }
    }

    public static String responseText(HttpRequestResponse rr) {
        if (rr == null || !rr.hasResponse()) {
            return "<no response>";
        }
        return responseText(rr.response());
    }

    public static String responseText(HttpResponse resp) {
        if (resp == null) {
            return "<no response>";
        }
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("HTTP ").append(resp.statusCode()).append(' ')
                    .append(resp.reasonPhrase() == null ? "" : resp.reasonPhrase()).append('\n');
            for (var h : resp.headers()) {
                sb.append(h.name()).append(": ").append(h.value()).append('\n');
            }
            sb.append('\n');
            sb.append(resp.bodyToString());
            return truncate(sb.toString());
        } catch (RuntimeException e) {
            return "<unavailable>";
        }
    }

    private static String truncate(String s) {
        if (s == null) {
            return "";
        }
        if (s.length() <= MAX_BODY) {
            return s;
        }
        return s.substring(0, MAX_BODY) + "\n...[truncated " + (s.length() - MAX_BODY) + " bytes]...";
    }
}
