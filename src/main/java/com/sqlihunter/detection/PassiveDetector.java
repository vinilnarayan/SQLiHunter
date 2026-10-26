package com.sqlihunter.detection;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.sqlihunter.config.ScanConfigView;
import com.sqlihunter.findings.Confidence;
import com.sqlihunter.findings.Finding;
import com.sqlihunter.findings.Severity;
import com.sqlihunter.mutation.ParameterLocation;

import java.util.List;

/**
 * Passive detection: inspects a request/response pair that Burp already
 * captured, generating NO new traffic. A database error string on its own is
 * only information disclosure, so passive findings are capped at LOW severity /
 * LOW confidence and are explicitly marked as requiring active confirmation.
 */
public final class PassiveDetector {

    public List<Finding> analyze(HttpRequestResponse rr, ScanConfigView config) {
        if (rr == null || !rr.hasResponse()) {
            return List.of();
        }
        if (!config.fingerprintingEnabled() && !config.passiveEnabled()) {
            return List.of();
        }
        String body = rr.response().bodyToString();
        List<SqlErrorSignatures.Match> matches = SqlErrorSignatures.findMatches(body);
        if (matches.isEmpty()) {
            return List.of();
        }

        double maxWeight = matches.stream().mapToDouble(SqlErrorSignatures.Match::weight).max().orElse(0);
        DatabaseFingerprinter.Result fp = DatabaseFingerprinter.fingerprint(matches);

        HttpRequest req = rr.request();
        String host = safeHost(req);
        String endpoint = safePath(req);

        Severity severity = maxWeight >= 0.85 ? Severity.LOW : Severity.INFORMATIONAL;
        Confidence confidence = maxWeight >= 0.85 ? Confidence.LOW : Confidence.POTENTIAL;

        StringBuilder evidence = new StringBuilder();
        evidence.append("Database error signature(s) observed in the response:\n");
        for (SqlErrorSignatures.Match m : matches) {
            evidence.append("  • [").append(m.family().display()).append("] ")
                    .append(m.matchedText()).append('\n');
        }
        evidence.append("This is passive observation only; injection is NOT demonstrated. "
                + "A database error can also be triggered by benign malformed input.");

        Finding f = Finding.builder()
                .title("Database error message disclosed in response")
                .type("Passive - Database error disclosure")
                .severity(severity)
                .confidence(confidence)
                .host(host)
                .endpoint(endpoint)
                .method(safeMethod(req))
                .paramName("(response body)")
                .paramLocation(ParameterLocation.BODY)
                .dbFamily(fp.family)
                .detectionMethod("Passive response analysis (no traffic generated)")
                .evidenceSummary(evidence.toString())
                .httpStatus(rr.response().statusCode())
                .limitations("Passive only. A database error string does not prove an injectable "
                        + "parameter. Run active error-based/boolean tests to confirm.")
                .preconditions("A response already captured by Burp contains a database error string.")
                .reproStep("Review the captured response for the database error text shown above.")
                .reproStep("Run SQLiHunter active testing against the parameters of this request to confirm.")
                .baselineRequest(Evidence.requestText(req))
                .baselineResponse(Evidence.responseText(rr))
                .repeaterEntry("Captured request", req)
                .build();

        return List.of(f);
    }

    private static String safeHost(HttpRequest req) {
        try { return req.httpService().host(); } catch (RuntimeException e) { return ""; }
    }

    private static String safePath(HttpRequest req) {
        try { return req.pathWithoutQuery(); } catch (RuntimeException e) { return ""; }
    }

    private static String safeMethod(HttpRequest req) {
        try { return req.method(); } catch (RuntimeException e) { return ""; }
    }
}
