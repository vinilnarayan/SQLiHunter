package com.sqlihunter.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class RateLimiterTest {

    @Test
    void throttlesToConfiguredRate() throws InterruptedException {
        // 10 req/s => ~100ms spacing; 5 acquisitions should take >= ~400ms.
        RateLimiter limiter = new RateLimiter(10.0);
        long start = System.nanoTime();
        for (int i = 0; i < 5; i++) {
            limiter.acquire();
        }
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;
        assertTrue(elapsedMs >= 350, "expected throttling delay, got " + elapsedMs + "ms");
    }
}
