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
 * Conservative, opt-in time-based blind detection. Disabled by default. Sends a
 * benign control to establish a latency reference, then a single delay payload;
 * a candidate delay is re-measured once to guard against jitter. Results are
 * always reported as SUSPECTED (never HIGH/CONFIRMED) because timing is noisy.
 */
public final class TimeBasedDetector implements ActiveDetector {

    @Override
    public String name() {
        return "time-based";
    }

    @Override
    public List<Finding> test(Param param, ActiveContext ac) {
        if (!ac.config().timeBasedEnabled() || !ac.baseline().ok()) {
            return List.of();
        }
        int delaySeconds = ac.config().timeBasedDelaySeconds();
        long delayMillis = delaySeconds * 1000L;
        int maxProbes = ac.config().timeBasedMaxProbesPerParam();

        // Control latency: benign payload that must NOT delay.
        HttpRequest controlReq = ac.mutator().mutate(ac.original(), param, Payloads.timingControl(param.originalValue()));
        if (controlReq == null) {
            return List.of();
        }
        BurpHttpClient.Result control = ac.sender().send(controlReq);
        if (control == null) {
            return List.of();
        }
        long controlMillis = control.ok() ? control.elapsedMillis() : ac.baseline().elapsedMillis();
        // A delay counts only if it exceeds control by at least 80% of the requested delay.
        long threshold = controlMillis + (long) (delayMillis * 0.8);

        int probes = 0;
        for (Payloads.TimePayload tp : Payloads.timePayloads()) {
            if (probes >= maxProbes) {
                break;
            }
            String logical = param.originalValue() + tp.render(delaySeconds);
            HttpRequest req = ac.mutator().mutate(ac.original(), param, logical);
            if (req == null) {
                continue;
            }
            BurpHttpClient.Result r1 = ac.sender().send(req);
            probes++;
            if (r1 == null) {
                return List.of();
            }
            if (!r1.ok() || r1.elapsedMillis() < threshold) {
                continue;
            }
            // Candidate: confirm once more to rule out a one-off slow response.
            if (probes >= maxProbes) {
                break;
            }
            BurpHttpClient.Result r2 = ac.sender().send(req);
            probes++;
            if (r2 == null) {
                return List.of();
            }
            if (!r2.ok() || r2.elapsedMillis() < threshold) {
                continue; // not reproducible -> not reported
            }

            String ev = String.format(
                    "Injecting a %ds delay payload (%s) produced consistently elevated response times.%n"
                    + "  control latency        = %d ms%n"
                    + "  delayed request #1     = %d ms%n"
                    + "  delayed request #2     = %d ms%n"
                    + "  detection threshold    = %d ms%n"
                    + "Timing is inherently noisy; treat this as SUSPECTED pending manual confirmation.",
                    delaySeconds, tp.family, controlMillis, r1.elapsedMillis(), r2.elapsedMillis(), threshold);

            Finding f = Finding.builder()
                    .title("Suspected time-based blind SQL injection in parameter '" + param.name() + "'")
                    .type("Time-based blind SQL injection (suspected)")
                    .severity(Severity.MEDIUM)
                    .confidence(Confidence.MEDIUM)
                    .host(ac.host())
                    .endpoint(ac.endpoint())
                    .method(ac.method())
                    .paramName(param.name())
                    .paramLocation(param.location())
                    .detectionMethod("Active time-based: control vs. delayed payload, re-measured")
                    .evidenceSummary(ev)
                    .httpStatus(r1.statusCode())
                    .limitations("SUSPECTED only. Network jitter and server load can imitate delays. "
                            + "Confirm with additional, independent measurements before escalating.")
                    .preconditions("Time-based testing explicitly enabled by the tester; parameter reaches a SQL query.")
                    .reproStep("Send the control request and note its latency (~" + controlMillis + " ms).")
                    .reproStep("Send with " + param.name() + " carrying a " + delaySeconds
                            + "s delay payload for " + tp.family + " and observe the increased latency.")
                    .reproStep("Repeat; a reproducible delay proportional to the payload supports the finding.")
                    .baselineRequest(Evidence.requestText(controlReq))
                    .baselineResponse(Evidence.responseText(control.requestResponse()))
                    .testRequest(Evidence.requestText(req))
                    .testResponse(Evidence.responseText(r1.requestResponse()))
                    .repeaterEntry("Control / no-delay (" + param.name() + ")", controlReq)
                    .repeaterEntry("Delay payload (" + param.name() + ")", req)
                    .build();
            return List.of(f);
        }
        return List.of();
    }
}
