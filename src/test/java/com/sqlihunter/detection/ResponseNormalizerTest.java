package com.sqlihunter.detection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** Negative/false-positive focused tests: dynamic noise must not look like a boolean difference. */
class ResponseNormalizerTest {

    private final ResponseNormalizer n = new ResponseNormalizer();

    @Test
    void dynamicTokensDoNotReduceSimilarity() {
        String a = "<html><input name=csrf_token value=\"abc123def456abc1\"> Welcome user. 2024-01-01T10:00:00Z</html>";
        String b = "<html><input name=csrf_token value=\"zzz999zzz999zzz9\"> Welcome user. 2024-06-15T22:33:44Z</html>";
        double sim = n.similarity(a, b);
        assertTrue(sim >= 0.95, "normalized responses differing only in tokens/timestamps must stay similar, was " + sim);
    }

    @Test
    void genuinelyDifferentContentIsDissimilar() {
        String a = "<html>Showing 42 matching records for your account</html>";
        String b = "<html>No results found. Access denied.</html>";
        double sim = n.similarity(a, b);
        assertTrue(sim < 0.9, "clearly different pages must diverge, was " + sim);
    }

    @Test
    void identicalIsOne() {
        assertTrue(n.similarity("same body", "same body") >= 0.999);
    }
}
