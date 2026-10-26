package com.sqlihunter.detection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Verifies the redirect-Location normalization that lets boolean-blind detect
 * auth-bypass style findings (empty body; signal is in status + Location).
 */
class ResponseFactsTest {

    @Test
    void absoluteAndRelativeLocationsReduceToPath() {
        assertEquals("/bank/main.jsp",
                ResponseFacts.normalizeLocation("https://demo.testfire.net/bank/main.jsp"));
        assertEquals("/login.jsp", ResponseFacts.normalizeLocation("/login.jsp"));
        assertEquals("login.jsp", ResponseFacts.normalizeLocation("login.jsp"));
    }

    @Test
    void queryAndTrailingSlashStripped() {
        assertEquals("/bank/main.jsp",
                ResponseFacts.normalizeLocation("/bank/main.jsp?sid=abc123"));
        assertEquals("/bank/main.jsp",
                ResponseFacts.normalizeLocation("/bank/main.jsp/"));
    }

    @Test
    void successAndFailureRedirectsDiffer() {
        // The exact signal from the AltoroMutual login auth-bypass.
        String success = ResponseFacts.normalizeLocation("/bank/main.jsp");
        String failure = ResponseFacts.normalizeLocation("login.jsp");
        assertNotEquals(success, failure);
    }

    @Test
    void emptyLocationIsEmpty() {
        assertEquals("", ResponseFacts.normalizeLocation(null));
        assertEquals("", ResponseFacts.normalizeLocation(""));
    }
}
