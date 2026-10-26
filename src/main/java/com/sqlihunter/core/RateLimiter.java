package com.sqlihunter.core;

/**
 * Simple global throughput limiter: blocks callers so that no more than
 * {@code requestsPerSecond} acquisitions proceed per second across all worker
 * threads. Interruptible so scans can be cancelled while waiting.
 */
public final class RateLimiter {

    private final double requestsPerSecond;
    private final Object lock = new Object();
    private long nextSlotNanos = System.nanoTime();

    public RateLimiter(double requestsPerSecond) {
        this.requestsPerSecond = Math.max(0.1, requestsPerSecond);
    }

    /** Blocks until a slot is available. Throws InterruptedException if cancelled. */
    public void acquire() throws InterruptedException {
        long intervalNanos = (long) (1_000_000_000L / requestsPerSecond);
        long waitNanos;
        synchronized (lock) {
            long now = System.nanoTime();
            if (now < nextSlotNanos) {
                waitNanos = nextSlotNanos - now;
                nextSlotNanos += intervalNanos;
            } else {
                waitNanos = 0;
                nextSlotNanos = now + intervalNanos;
            }
        }
        if (waitNanos > 0) {
            long millis = waitNanos / 1_000_000L;
            int nanos = (int) (waitNanos % 1_000_000L);
            Thread.sleep(millis, nanos);
        }
    }
}
