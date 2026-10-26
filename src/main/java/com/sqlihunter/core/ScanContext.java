package com.sqlihunter.core;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Live, thread-safe state of a running scan: progress counters plus the
 * cancellation / pause control used cooperatively by all workers. Also enforces
 * the request budget via {@link #tryConsumeBudget()}.
 */
public final class ScanContext {

    public interface ProgressListener {
        void onProgress(ScanContext ctx);
        void onFinished(ScanContext ctx);
    }

    private final int maxRequests;
    private final AtomicInteger requestsSent = new AtomicInteger();
    private final AtomicInteger parametersTotal = new AtomicInteger();
    private final AtomicInteger parametersTested = new AtomicInteger();
    private final AtomicInteger findings = new AtomicInteger();
    private final AtomicInteger errors = new AtomicInteger();
    private final AtomicInteger skipped = new AtomicInteger();
    private final AtomicLong startMillis = new AtomicLong(System.currentTimeMillis());
    private final AtomicReference<String> currentTarget = new AtomicReference<>("");

    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private final AtomicBoolean paused = new AtomicBoolean(false);
    private final Object pauseLock = new Object();

    private volatile ProgressListener listener;

    public ScanContext(int maxRequests) {
        this.maxRequests = maxRequests;
    }

    public void setListener(ProgressListener l) {
        this.listener = l;
    }

    /** Atomically reserve one unit of the request budget. */
    public boolean tryConsumeBudget() {
        while (true) {
            int cur = requestsSent.get();
            if (cur >= maxRequests) {
                return false;
            }
            if (requestsSent.compareAndSet(cur, cur + 1)) {
                fireProgress();
                return true;
            }
        }
    }

    public boolean budgetExhausted() {
        return requestsSent.get() >= maxRequests;
    }

    // ---- cancellation / pause ----
    public void cancel() {
        cancelled.set(true);
        resume(); // wake any paused workers so they can observe cancellation
    }

    public boolean isCancelled() {
        return cancelled.get();
    }

    public void pause() {
        paused.set(true);
        fireProgress();
    }

    public void resume() {
        paused.set(false);
        synchronized (pauseLock) {
            pauseLock.notifyAll();
        }
        fireProgress();
    }

    public boolean isPaused() {
        return paused.get();
    }

    /** Cooperative checkpoint: blocks while paused, returns false if cancelled. */
    public boolean checkpoint() {
        if (cancelled.get()) {
            return false;
        }
        while (paused.get() && !cancelled.get()) {
            synchronized (pauseLock) {
                try {
                    pauseLock.wait(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        return !cancelled.get();
    }

    // ---- counters ----
    public void incParametersTested() { parametersTested.incrementAndGet(); fireProgress(); }
    public void addParametersTotal(int n) { parametersTotal.addAndGet(n); fireProgress(); }
    public void incFindings() { findings.incrementAndGet(); fireProgress(); }
    public void incErrors() { errors.incrementAndGet(); fireProgress(); }
    public void incSkipped() { skipped.incrementAndGet(); fireProgress(); }
    public void setCurrentTarget(String t) { currentTarget.set(t); fireProgress(); }

    public int requestsSent() { return requestsSent.get(); }
    public int requestsRemaining() { return Math.max(0, maxRequests - requestsSent.get()); }
    public int maxRequests() { return maxRequests; }
    public int parametersTotal() { return parametersTotal.get(); }
    public int parametersTested() { return parametersTested.get(); }
    public int findings() { return findings.get(); }
    public int errors() { return errors.get(); }
    public int skipped() { return skipped.get(); }
    public String currentTarget() { return currentTarget.get(); }
    public long elapsedMillis() { return System.currentTimeMillis() - startMillis.get(); }

    private void fireProgress() {
        ProgressListener l = listener;
        if (l != null) {
            l.onProgress(this);
        }
    }

    public void fireFinished() {
        ProgressListener l = listener;
        if (l != null) {
            l.onFinished(this);
        }
    }
}
