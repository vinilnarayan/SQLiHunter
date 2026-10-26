package com.sqlihunter.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.sqlihunter.detection.ActiveContext;
import com.sqlihunter.detection.ActiveDetector;
import com.sqlihunter.detection.BooleanBlindDetector;
import com.sqlihunter.detection.ErrorBasedDetector;
import com.sqlihunter.detection.PassiveDetector;
import com.sqlihunter.detection.ResponseNormalizer;
import com.sqlihunter.detection.Sender;
import com.sqlihunter.detection.TimeBasedDetector;
import com.sqlihunter.findings.Finding;
import com.sqlihunter.findings.FindingsStore;
import com.sqlihunter.http.BurpHttpClient;
import com.sqlihunter.mutation.Param;
import com.sqlihunter.mutation.ParameterLocation;
import com.sqlihunter.mutation.RequestMutator;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * Orchestrates a scan: passive analysis, then (if enabled and in scope) active
 * testing of each selected parameter through a bounded worker pool, enforcing
 * budget, rate, concurrency, timeout, pause/resume/cancel, and authentication
 * loss handling. Exceptions in any detector are contained so Burp never crashes.
 */
public final class ScanEngine {

    private static final Pattern AUTH_LOSS_BODY = Pattern.compile(
            "(?i)(session (has )?expired|please (log|sign) ?in|login required|not authori[sz]ed|authentication required)");

    private final MontoyaApi api;
    private final ScanConfig config;
    private final FindingsStore store;
    private final RequestMutator mutator = new RequestMutator();

    private final AtomicReference<ScanContext> current = new AtomicReference<>();
    private volatile ExecutorService pool;
    private volatile Thread orchestrator;
    private volatile Thread watchdog;

    public ScanEngine(MontoyaApi api, ScanConfig config, FindingsStore store) {
        this.api = api;
        this.config = config;
        this.store = store;
    }

    public boolean isRunning() {
        ScanContext c = current.get();
        return c != null && !c.isCancelled();
    }

    public ScanContext currentContext() {
        return current.get();
    }

    /**
     * Starts a scan of a single captured request. Passive analysis always runs;
     * active testing runs only if enabled in config and the target is in scope.
     * Returns the live {@link ScanContext}, or null if a scan is already running.
     *
     * @param selected optional parameter subset; null/empty means "all eligible".
     */
    public ScanContext startScan(HttpRequestResponse base, List<Param> selected) {
        if (isRunning()) {
            return null;
        }
        HttpRequest original = base.request();
        BurpHttpClient client = new BurpHttpClient(api, config.responseTimeoutMillis());

        // ---- passive first (no traffic) ----
        try {
            PassiveDetector passive = new PassiveDetector();
            for (Finding f : passive.analyze(base, config)) {
                store.add(f);
            }
        } catch (RuntimeException ex) {
            api.logging().logToError("Passive analysis error", ex);
        }

        if (!config.activeEnabled()) {
            api.logging().logToOutput("[SQLiHunter] Passive-only scan complete.");
            return null;
        }

        // ---- scope gate for active testing ----
        ScopeController scope = new ScopeController(config, api);
        String rejection = scope.rejectionReason(original);
        if (rejection != null) {
            api.logging().logToOutput("[SQLiHunter] Active testing blocked by scope: " + rejection);
            return null;
        }
        if (!scope.inBurpScope(original)) {
            api.logging().logToOutput("[SQLiHunter] Note: target is not in Burp's Target > Scope "
                    + "(allowed by SQLiHunter's own allow-list). Add it to Burp scope to silence this note.");
        }

        // ---- parameter discovery & filtering ----
        RequestMutator.Discovery discovery = mutator.discover(
                original, config.testHeaders(), config.enabledHeaderNames(), config.testPath());
        List<Param> params = filter(discovery.params, selected);

        ScanContext ctx = new ScanContext(config.maxRequests());
        ctx.addParametersTotal(params.size());
        ctx.setCurrentTarget(safeTarget(original));
        current.set(ctx);

        for (String w : discovery.warnings) {
            api.logging().logToOutput("[SQLiHunter] " + w);
            ctx.incSkipped();
        }

        RateLimiter limiter = new RateLimiter(config.requestsPerSecond());
        AtomicInteger consecutiveAuthLoss = new AtomicInteger(0);
        Sender sender = req -> {
            if (!ctx.checkpoint()) {
                return null;
            }
            if (!ctx.tryConsumeBudget()) {
                return null;
            }
            try {
                limiter.acquire();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
            BurpHttpClient.Result r = client.send(req);
            if (!r.ok()) {
                ctx.incErrors();
            }
            handleAuthLoss(ctx, r, consecutiveAuthLoss);
            return r;
        };

        ResponseNormalizer normalizer = new ResponseNormalizer();
        List<ActiveDetector> detectors = buildDetectors();

        this.pool = Executors.newFixedThreadPool(config.maxConcurrency(), namedThreads());
        startWatchdog(ctx, config.scanTimeoutSeconds());

        orchestrator = new Thread(() -> runActive(ctx, base, original, params, sender, normalizer, detectors),
                "sqlihunter-orchestrator");
        orchestrator.setDaemon(true);
        orchestrator.start();
        return ctx;
    }

    private void runActive(ScanContext ctx, HttpRequestResponse base, HttpRequest original,
                           List<Param> params, Sender sender, ResponseNormalizer normalizer,
                           List<ActiveDetector> detectors) {
        try {
            // Establish a fresh baseline through the same gated path.
            BurpHttpClient.Result baseline = sender.send(original);
            if (baseline == null) {
                api.logging().logToOutput("[SQLiHunter] Scan stopped before baseline could be established.");
                return;
            }
            ActiveContext ac = new ActiveContext(original, baseline, sender, mutator, normalizer, config);

            List<Future<?>> futures = new ArrayList<>();
            for (Param p : params) {
                if (ctx.isCancelled()) {
                    break;
                }
                if (config.isParamExcluded(p.name())) {
                    ctx.incSkipped();
                    api.logging().logToOutput("[SQLiHunter] Skipped excluded parameter: " + p.name());
                    continue;
                }
                futures.add(pool.submit(() -> testParam(ctx, ac, p, detectors)));
            }
            for (Future<?> f : futures) {
                try {
                    f.get();
                } catch (Exception ignored) {
                    // individual task failures already contained
                }
            }
        } catch (RuntimeException ex) {
            api.logging().logToError("Scan orchestration error", ex);
        } finally {
            shutdownPool();
            api.logging().logToOutput(String.format(
                    "[SQLiHunter] Scan finished. requests=%d findings=%d errors=%d skipped=%d elapsed=%dms",
                    ctx.requestsSent(), ctx.findings(), ctx.errors(), ctx.skipped(), ctx.elapsedMillis()));
            ctx.fireFinished();
            current.set(null);
        }
    }

    private void testParam(ScanContext ctx, ActiveContext ac, Param p, List<ActiveDetector> detectors) {
        if (!ctx.checkpoint()) {
            return;
        }
        ctx.setCurrentTarget(ac.host() + ac.endpoint() + " [" + p + "]");
        for (ActiveDetector d : detectors) {
            if (!ctx.checkpoint() || ctx.budgetExhausted()) {
                break;
            }
            try {
                for (Finding f : d.test(p, ac)) {
                    if (store.add(f)) {
                        ctx.incFindings();
                    }
                }
            } catch (RuntimeException ex) {
                ctx.incErrors();
                api.logging().logToError("Detector '" + d.name() + "' failed on " + p, ex);
            }
        }
        ctx.incParametersTested();
    }

    private List<ActiveDetector> buildDetectors() {
        List<ActiveDetector> list = new ArrayList<>();
        if (config.errorBasedEnabled()) {
            list.add(new ErrorBasedDetector());
        }
        if (config.booleanBlindEnabled()) {
            list.add(new BooleanBlindDetector());
        }
        if (config.timeBasedEnabled()) {
            list.add(new TimeBasedDetector());
        }
        return list;
    }

    private List<Param> filter(List<Param> all, List<Param> selected) {
        List<Param> out = new ArrayList<>();
        for (Param p : all) {
            if (!locationEnabled(p.location())) {
                continue;
            }
            if (selected != null && !selected.isEmpty() && !selected.contains(p)) {
                continue;
            }
            out.add(p);
        }
        return out;
    }

    private boolean locationEnabled(ParameterLocation loc) {
        switch (loc) {
            case URL: return config.testUrl();
            case BODY: return config.testBody();
            case COOKIE: return config.testCookies();
            case JSON: return config.testJson();
            case XML: return config.testXml();
            case HEADER: return config.testHeaders();
            case PATH: return config.testPath();
            case MULTIPART: return config.testBody();
            default: return false;
        }
    }

    private void handleAuthLoss(ScanContext ctx, BurpHttpClient.Result r, AtomicInteger counter) {
        boolean authLost = false;
        if (r.ok()) {
            short sc = r.statusCode();
            if (sc == 401 || sc == 403) {
                authLost = true;
            } else if (AUTH_LOSS_BODY.matcher(r.responseBody()).find()) {
                authLost = true;
            }
        }
        if (authLost) {
            if (counter.incrementAndGet() >= 3 && !ctx.isPaused()) {
                ctx.pause();
                api.logging().logToOutput("[SQLiHunter] Possible authentication loss detected "
                        + "(repeated 401/403 or login responses). Scan PAUSED. Re-authenticate in the "
                        + "browser/Burp, then Resume.");
            }
        } else {
            counter.set(0);
        }
    }

    private void startWatchdog(ScanContext ctx, int timeoutSeconds) {
        watchdog = new Thread(() -> {
            long deadline = System.currentTimeMillis() + timeoutSeconds * 1000L;
            while (!ctx.isCancelled() && current.get() == ctx) {
                if (System.currentTimeMillis() >= deadline) {
                    api.logging().logToOutput("[SQLiHunter] Scan timeout reached; cancelling.");
                    ctx.cancel();
                    break;
                }
                try {
                    Thread.sleep(250);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }, "sqlihunter-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    public void pause() {
        ScanContext c = current.get();
        if (c != null) {
            c.pause();
        }
    }

    public void resume() {
        ScanContext c = current.get();
        if (c != null) {
            c.resume();
        }
    }

    public void stop() {
        ScanContext c = current.get();
        if (c != null) {
            c.cancel();
        }
        shutdownPool();
    }

    private void shutdownPool() {
        ExecutorService p = pool;
        if (p != null) {
            p.shutdownNow();
            try {
                p.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static ThreadFactory namedThreads() {
        AtomicInteger n = new AtomicInteger();
        return r -> {
            Thread t = new Thread(r, "sqlihunter-worker-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }

    private static String safeTarget(HttpRequest req) {
        try {
            return req.method() + " " + req.url();
        } catch (RuntimeException e) {
            return "(unknown target)";
        }
    }
}
