package com.sqlihunter.findings;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class FindingRepeaterTest {

    private HttpRequest stubRequest() {
        return (HttpRequest) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class[]{HttpRequest.class},
                (p, m, a) -> null);
    }

    @Test
    void repeaterEntriesStoredInOrderAndNullSkipped() {
        HttpRequest base = stubRequest();
        HttpRequest t = stubRequest();
        HttpRequest f = stubRequest();
        Finding finding = Finding.builder()
                .repeaterEntry("Baseline", base)
                .repeaterEntry("TRUE variant", t)
                .repeaterEntry("ignored", null) // must be skipped
                .repeaterEntry("FALSE variant", f)
                .build();

        assertEquals(3, finding.repeaterEntries().size(), "null request must not be stored");
        assertEquals("Baseline", finding.repeaterEntries().get(0).label());
        assertSame(base, finding.repeaterEntries().get(0).request());
        assertEquals("TRUE variant", finding.repeaterEntries().get(1).label());
        assertEquals("FALSE variant", finding.repeaterEntries().get(2).label());
    }

    @Test
    void noRepeaterEntriesByDefault() {
        assertEquals(0, Finding.builder().build().repeaterEntries().size());
    }
}
