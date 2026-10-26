package com.sqlihunter.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * The ONLY component in SQLiHunter that emits network traffic.
 *
 * <p>Every request the extension sends is dispatched through Burp's official
 * Montoya transport, {@code api.http().sendRequest(...)}. No other HTTP client,
 * socket, or library is used anywhere in the codebase. Keeping transport in a
 * single class makes that guarantee auditable (see docs/HTTP_REQUEST_PATHS.md).
 *
 * <p>Because requests go through Burp, they inherit Burp's configured upstream
 * proxy chain and TLS handling. Note: extension-generated requests do NOT
 * automatically appear in Proxy history (Proxy history records traffic that
 * passes through the Proxy listener, which this does not). They are, however,
 * visible in Burp's Logger and can be logged by the extension itself.
 */
public final class BurpHttpClient {

    /** Outcome of a single send: either a response, or a transport error. */
    public static final class Result {
        private final HttpRequest request;
        private final HttpRequestResponse requestResponse;
        private final long elapsedMillis;
        private final String error;

        private Result(HttpRequest request, HttpRequestResponse rr, long elapsedMillis, String error) {
            this.request = request;
            this.requestResponse = rr;
            this.elapsedMillis = elapsedMillis;
            this.error = error;
        }

        public boolean ok() {
            return error == null && requestResponse != null && requestResponse.hasResponse();
        }

        public HttpRequest request() { return request; }
        public HttpRequestResponse requestResponse() { return requestResponse; }
        public long elapsedMillis() { return elapsedMillis; }
        public String error() { return error; }

        public short statusCode() {
            return ok() ? requestResponse.response().statusCode() : -1;
        }

        public String responseBody() {
            return ok() ? requestResponse.response().bodyToString() : "";
        }

        public int responseLength() {
            if (!ok()) {
                return 0;
            }
            return requestResponse.response().toByteArray().length();
        }
    }

    private final MontoyaApi api;
    private final long responseTimeoutMillis;

    public BurpHttpClient(MontoyaApi api, long responseTimeoutMillis) {
        this.api = api;
        this.responseTimeoutMillis = responseTimeoutMillis;
    }

    /**
     * Sends a request via Burp and measures round-trip latency.
     * Never throws: transport failures are captured in {@link Result#error()}.
     */
    public Result send(HttpRequest request) {
        RequestOptions options = RequestOptions.requestOptions()
                .withResponseTimeout(responseTimeoutMillis);
        long start = System.nanoTime();
        try {
            // === Official Burp HTTP API. The single network egress point. ===
            HttpRequestResponse rr = api.http().sendRequest(request, options);
            long elapsed = (System.nanoTime() - start) / 1_000_000L;
            return new Result(request, rr, elapsed, null);
        } catch (RuntimeException ex) {
            long elapsed = (System.nanoTime() - start) / 1_000_000L;
            return new Result(request, null, elapsed, ex.getClass().getSimpleName() + ": " + ex.getMessage());
        }
    }
}
