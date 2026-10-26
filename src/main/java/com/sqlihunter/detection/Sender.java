package com.sqlihunter.detection;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.sqlihunter.http.BurpHttpClient;

/**
 * Gate through which detectors send requests. The engine's implementation
 * enforces, in order: cancellation/pause checkpoint, request-budget reservation,
 * rate limiting, then dispatch via {@link BurpHttpClient} (Burp's HTTP API).
 * Returns {@code null} when the scan is cancelled or the budget is exhausted,
 * signalling the detector to stop.
 */
public interface Sender {
    BurpHttpClient.Result send(HttpRequest request);
}
