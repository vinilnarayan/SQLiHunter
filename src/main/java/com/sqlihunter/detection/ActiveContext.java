package com.sqlihunter.detection;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.sqlihunter.config.ScanConfigView;
import com.sqlihunter.http.BurpHttpClient;
import com.sqlihunter.mutation.RequestMutator;

/**
 * Immutable per-request context passed to active detectors. The baseline is the
 * result of re-sending the original request once (through {@link Sender}), used
 * as the comparison point for all differential checks.
 */
public final class ActiveContext {

    private final HttpRequest original;
    private final BurpHttpClient.Result baseline;
    private final Sender sender;
    private final RequestMutator mutator;
    private final ResponseNormalizer normalizer;
    private final ScanConfigView config;
    private final String host;
    private final String endpoint;
    private final String method;

    public ActiveContext(HttpRequest original, BurpHttpClient.Result baseline, Sender sender,
                         RequestMutator mutator, ResponseNormalizer normalizer, ScanConfigView config) {
        this.original = original;
        this.baseline = baseline;
        this.sender = sender;
        this.mutator = mutator;
        this.normalizer = normalizer;
        this.config = config;
        this.host = safe(() -> original.httpService().host());
        this.endpoint = safe(original::pathWithoutQuery);
        this.method = safe(original::method);
    }

    public HttpRequest original() { return original; }
    public BurpHttpClient.Result baseline() { return baseline; }
    public Sender sender() { return sender; }
    public RequestMutator mutator() { return mutator; }
    public ResponseNormalizer normalizer() { return normalizer; }
    public ScanConfigView config() { return config; }
    public String host() { return host; }
    public String endpoint() { return endpoint; }
    public String method() { return method; }

    private interface Supplier { String get(); }
    private static String safe(Supplier s) {
        try { return s.get(); } catch (RuntimeException e) { return ""; }
    }
}
