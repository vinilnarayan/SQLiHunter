package com.sqlihunter.detection;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.sqlihunter.findings.Confidence;
import com.sqlihunter.findings.Finding;
import com.sqlihunter.findings.Severity;
import com.sqlihunter.http.BurpHttpClient;
import com.sqlihunter.mutation.Param;
import com.sqlihunter.mutation.Payloads;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Error-based active detection. Injects syntax-breaking probes and reports a
 * finding only when a database error signature appears that was NOT present in
 * the baseline response. Requires signatures corroborated across probes to
 * reach HIGH confidence, keeping false positives low.
 */
public final class ErrorBasedDetector implements ActiveDetector {

    @Override
    public String name() {
        return "error-based";
    }

    @Override
    public List<Finding> test(Param param, ActiveContext ac) {
        if (!ac.config().errorBasedEnabled() || !ac.baseline().ok()) {
            return List.of();
        }
        String baselineBody = DetectorSupport.cap(ac.baseline().responseBody(), ac.config().maxResponseBytes());
        Set<String> baselineSigs = new HashSet<>();
        for (SqlErrorSignatures.Match m : SqlErrorSignatures.findMatches(baselineBody)) {
            baselineSigs.add(m.description());
        }

        List<SqlErrorSignatures.Match> corroborating = new ArrayList<>();
        Set<String> triggeringProbes = new HashSet<>();
        BurpHttpClient.Result firstHit = null;
        HttpRequest firstHitReq = null;

        for (String probe : Payloads.ERROR_PROBES) {
            String logical = param.originalValue() + probe;
            HttpRequest mutated = ac.mutator().mutate(ac.original(), param, logical);
            if (mutated == null) {
                continue;
            }
            BurpHttpClient.Result r = ac.sender().send(mutated);
            if (r == null) {
                break; // cancelled or budget exhausted
            }
            if (!r.ok()) {
                continue;
            }
            String body = DetectorSupport.cap(r.responseBody(), ac.config().maxResponseBytes());
            for (SqlErrorSignatures.Match m : SqlErrorSignatures.findMatches(body)) {
                if (!baselineSigs.contains(m.description())) {
                    corroborating.add(m);
                    triggeringProbes.add(probe);
                    if (firstHit == null) {
                        firstHit = r;
                        firstHitReq = mutated;
                    }
                }
            }
        }

        if (corroborating.isEmpty()) {
            return List.of();
        }

        DatabaseFingerprinter.Result fp = DatabaseFingerprinter.fingerprint(corroborating);
        boolean strong = corroborating.stream().anyMatch(m -> m.weight() >= 0.9);
        boolean multi = triggeringProbes.size() >= 2;

        Severity severity;
        Confidence confidence;
        if (strong && multi) {
            severity = Severity.HIGH;
            confidence = Confidence.HIGH;
        } else if (strong || multi) {
            severity = Severity.MEDIUM;
            confidence = Confidence.MEDIUM;
        } else {
            severity = Severity.LOW;
            confidence = Confidence.LOW;
        }

        StringBuilder ev = new StringBuilder();
        ev.append("Injecting syntax-breaking input into this parameter produced database "
                + "error signatures absent from the baseline response.\n");
        ev.append("Triggering probes: ").append(triggeringProbes).append('\n');
        ev.append("Signatures observed:\n");
        for (SqlErrorSignatures.Match m : corroborating) {
            ev.append("  • [").append(m.family().display()).append("] ").append(m.matchedText()).append('\n');
        }

        Finding f = Finding.builder()
                .title("Error-based SQL injection in parameter '" + param.name() + "'")
                .type("Error-based SQL injection")
                .severity(severity)
                .confidence(confidence)
                .host(ac.host())
                .endpoint(ac.endpoint())
                .method(ac.method())
                .paramName(param.name())
                .paramLocation(param.location())
                .dbFamily(fp.family)
                .detectionMethod("Active error-based: baseline vs. injected-probe signature diff")
                .evidenceSummary(ev.toString())
                .httpStatus(firstHit.statusCode())
                .limitations("Confidence reflects corroboration across probes. A database error "
                        + "does not by itself prove data can be exfiltrated; manual verification is "
                        + "recommended before escalating severity.")
                .preconditions("Active testing authorised and enabled; the parameter reaches a SQL query.")
                .cvssVector(severity == Severity.HIGH
                        ? "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N" : null)
                .reproStep("Send the baseline request and note the response contains no SQL error.")
                .reproStep("Resend with " + param.location().display() + " parameter '" + param.name()
                        + "' set to its original value plus a probe such as a single quote (').")
                .reproStep("Observe the database error signature in the response shown below.")
                .baselineRequest(Evidence.requestText(ac.original()))
                .baselineResponse(Evidence.responseText(ac.baseline().requestResponse()))
                .testRequest(Evidence.requestText(firstHitReq))
                .testResponse(Evidence.responseText(firstHit.requestResponse()))
                .repeaterEntry("Baseline (" + param.name() + ")", ac.original())
                .repeaterEntry("Error probe (" + param.name() + ")", firstHitReq)
                .build();

        return List.of(f);
    }
}
