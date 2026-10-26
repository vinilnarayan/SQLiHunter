package com.sqlihunter.mutation;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Tests the encoding helpers that keep payloads from corrupting requests. */
class RequestMutatorEncodingTest {

    @Test
    void urlEncodeRoundTrip() {
        String raw = "a b&c=d'\"";
        String enc = RequestMutator.urlEncode(raw);
        assertFalse(enc.contains(" "), "spaces must be encoded");
        assertEquals(raw, RequestMutator.urlDecode(enc));
    }

    @Test
    void urlDecodeToleratesMalformedPercent() {
        // Must not throw on a stray percent; returns input unchanged.
        assertEquals("100%done", RequestMutator.urlDecode("100%done"));
    }

    @Test
    void xmlEscapeEscapesMarkup() {
        assertEquals("&lt;a&gt;&amp;&apos;&quot;", RequestMutator.xmlEscape("<a>&'\""));
    }

    @Test
    void stripCrLfPreventsHeaderInjection() {
        String evil = "value\r\nX-Injected: 1";
        String safe = RequestMutator.stripCrLf(evil);
        assertFalse(safe.contains("\r"));
        assertFalse(safe.contains("\n"));
        assertTrue(safe.startsWith("value"));
    }

    @Test
    void pathEncodeUsesPercent20ForSpaces() {
        assertEquals("a%20b", RequestMutator.pathEncode("a b"));
    }
}
