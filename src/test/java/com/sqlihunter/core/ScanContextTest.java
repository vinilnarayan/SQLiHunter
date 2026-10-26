package com.sqlihunter.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanContextTest {

    @Test
    void budgetIsEnforced() {
        ScanContext ctx = new ScanContext(3);
        assertTrue(ctx.tryConsumeBudget());
        assertTrue(ctx.tryConsumeBudget());
        assertTrue(ctx.tryConsumeBudget());
        assertFalse(ctx.tryConsumeBudget(), "4th must be denied");
        assertTrue(ctx.budgetExhausted());
        assertTrue(ctx.requestsSent() == 3);
    }

    @Test
    void cancellationStopsCheckpoint() {
        ScanContext ctx = new ScanContext(10);
        assertTrue(ctx.checkpoint());
        ctx.cancel();
        assertFalse(ctx.checkpoint());
        assertTrue(ctx.isCancelled());
    }

    @Test
    void pauseThenResumeIsObservable() throws Exception {
        ScanContext ctx = new ScanContext(10);
        ctx.pause();
        assertTrue(ctx.isPaused());
        // resume from another thread; checkpoint should unblock and return true
        Thread t = new Thread(() -> {
            try { Thread.sleep(100); } catch (InterruptedException ignored) { }
            ctx.resume();
        });
        t.start();
        long start = System.currentTimeMillis();
        boolean ok = ctx.checkpoint();
        assertTrue(ok);
        assertTrue(System.currentTimeMillis() - start >= 50, "checkpoint should have blocked while paused");
        t.join();
    }
}
