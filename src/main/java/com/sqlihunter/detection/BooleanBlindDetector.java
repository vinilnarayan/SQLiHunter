package com.sqlihunter.detection;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.sqlihunter.findings.Confidence;
import com.sqlihunter.findings.Finding;
import com.sqlihunter.findings.Severity;
import com.sqlihunter.http.BurpHttpClient;
import com.sqlihunter.mutation.Param;
import com.sqlihunter.mutation.Payloads;

import java.util.List;

/**
 * Boolean-based blind detection.
 *
 * <p>For a logically TRUE and a logically FALSE variant it compares full
 * response <em>fingerprints</em> — HTTP status, redirect {@code Location}, and
 * normalized body (see {@link ResponseFacts}) — not the body alone. A finding is
 * reported only when, consistently across repeated confirmations:
 * <ol>
 *   <li>repeated TRUE responses are stable (similar to each other),</li>
 *   <li>repeated FALSE responses are stable, and</li>
 *   <li>TRUE and FALSE diverge from each other.</li>
 * </ol>
 *
 * <p>This divergence-plus-stability model (rather than assuming TRUE must
 * resemble the captured baseline) is deliberate: for login forms the captured
 * request is usually a <em>failed</em> auth, and a successful SQL auth-bypass
 * flips status/redirect while leaving the body empty. Requiring "TRUE looks like
 * baseline" would miss exactly that case.
 */
public final class BooleanBlindDetector implements ActiveDetector {

    @Override
    public String name() {
        return "boolean-blind";
    }

    @Override
    public List<Finding> test(Param param, ActiveContext ac) {
        if (!ac.config().booleanBlindEnabled() || !ac.baseline().ok()) {
            return List.of();
        }
        int maxBytes = ac.config().maxResponseBytes();
        // Within-branch "same" threshold; divergence is simply "not similar".
        double sameThresh = ac.config().booleanTrueSimilarityThreshold();
        int confirmations = Math.max(1, ac.config().booleanConfirmations());

        ResponseFacts baselineFacts = ResponseFacts.from(ac.baseline(), ac.normalizer(), maxBytes);

        for (Payloads.BooleanPair pair : Payloads.booleanPairs(param.originalValue())) {
            boolean allConsistent = true;
            ResponseFacts firstTrue = null;
            ResponseFacts firstFalse = null;
            BurpHttpClient.Result evTrue = null;
            BurpHttpClient.Result evFalse = null;
            HttpRequest reqTrue = null;
            HttpRequest reqFalse = null;

            for (int i = 0; i < confirmations && allConsistent; i++) {
                HttpRequest tReq = ac.mutator().mutate(ac.original(), param, pair.truePayload);
                HttpRequest fReq = ac.mutator().mutate(ac.original(), param, pair.falsePayload);
                if (tReq == null || fReq == null) {
                    allConsistent = false;
                    break;
                }
                BurpHttpClient.Result tr = ac.sender().send(tReq);
                if (tr == null) {
                    return List.of(); // cancelled/budget
                }
                BurpHttpClient.Result fr = ac.sender().send(fReq);
                if (fr == null) {
                    return List.of();
                }
                if (!tr.ok() || !fr.ok()) {
                    allConsistent = false;
                    break;
                }
                ResponseFacts tf = ResponseFacts.from(tr, ac.normalizer(), maxBytes);
                ResponseFacts ff = ResponseFacts.from(fr, ac.normalizer(), maxBytes);

                boolean diverge = !tf.similarTo(ff, ac.normalizer(), sameThresh);
                boolean trueStable = firstTrue == null || tf.similarTo(firstTrue, ac.normalizer(), sameThresh);
                boolean falseStable = firstFalse == null || ff.similarTo(firstFalse, ac.normalizer(), sameThresh);

                if (!(diverge && trueStable && falseStable)) {
                    allConsistent = false;
                } else {
                    if (firstTrue == null) {
                        firstTrue = tf;
                        firstFalse = ff;
                    }
                    evTrue = tr;
                    evFalse = fr;
                    reqTrue = tReq;
                    reqFalse = fReq;
                }
            }

            if (allConsistent && evTrue != null) {
                Confidence confidence = confirmations >= 2 ? Confidence.HIGH : Confidence.MEDIUM;
                Severity severity = Severity.MEDIUM; // credible; impact not fully established

                // Note which branch (if either) matches the captured baseline.
                boolean trueMatchesBaseline = firstTrue.similarTo(baselineFacts, ac.normalizer(), sameThresh);
                boolean falseMatchesBaseline = firstFalse.similarTo(baselineFacts, ac.normalizer(), sameThresh);
                String baselineNote = trueMatchesBaseline ? "TRUE matches the captured baseline"
                        : falseMatchesBaseline ? "FALSE matches the captured baseline (e.g. auth-bypass style)"
                        : "neither variant matches the captured baseline";

                String ev = String.format(
                        "Consistent boolean differential over %d confirmation(s) using: %s%n"
                        + "  TRUE  response: %s%n"
                        + "  FALSE response: %s%n"
                        + "  TRUE and FALSE diverge; each is stable across confirmations.%n"
                        + "  Baseline relation: %s.%n"
                        + "Comparison used HTTP status + redirect Location + normalized body.",
                        confirmations, pair.description,
                        firstTrue.describe(), firstFalse.describe(), baselineNote);

                Finding f = Finding.builder()
                        .title("Boolean-based blind SQL injection in parameter '" + param.name() + "'")
                        .type("Boolean-based blind SQL injection")
                        .severity(severity)
                        .confidence(confidence)
                        .host(ac.host())
                        .endpoint(ac.endpoint())
                        .method(ac.method())
                        .paramName(param.name())
                        .paramLocation(param.location())
                        .detectionMethod("Active boolean-blind: status+redirect+body differential, repeated")
                        .evidenceSummary(ev)
                        .httpStatus(evTrue.statusCode())
                        .limitations("Differential inference only; no data was extracted. "
                                + "Impact depends on query context and should be confirmed manually.")
                        .preconditions("Active testing authorised and enabled; parameter influences a SQL WHERE/boolean context.")
                        .cvssVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")
                        .reproStep("Send with " + param.name() + " = \""
                                + escape(pair.truePayload) + "\" (logically TRUE) and record status + Location + body.")
                        .reproStep("Send with " + param.name() + " = \""
                                + escape(pair.falsePayload) + "\" (logically FALSE); the status/redirect/body differs.")
                        .reproStep("Repeat both to confirm each variant is stable and the difference is not dynamic noise.")
                        .baselineRequest(Evidence.requestText(ac.original()))
                        .baselineResponse(Evidence.responseText(ac.baseline().requestResponse()))
                        .testRequest("TRUE variant:\n" + Evidence.requestText(reqTrue)
                                + "\n\nFALSE variant:\n" + Evidence.requestText(reqFalse))
                        .testResponse("TRUE-variant response:\n"
                                + Evidence.responseText(evTrue.requestResponse())
                                + "\n\nFALSE-variant response (diverged):\n"
                                + Evidence.responseText(evFalse.requestResponse()))
                        .repeaterEntry("Baseline (" + param.name() + ")", ac.original())
                        .repeaterEntry("TRUE variant (" + param.name() + ")", reqTrue)
                        .repeaterEntry("FALSE variant (" + param.name() + ")", reqFalse)
                        .build();
                return List.of(f);
            }
        }
        return List.of();
    }

    private static String escape(String s) {
        return s.replace("\"", "\\\"");
    }
}
