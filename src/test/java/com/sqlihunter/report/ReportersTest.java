package com.sqlihunter.report;

import com.sqlihunter.detection.DbFamily;
import com.sqlihunter.findings.Confidence;
import com.sqlihunter.findings.Finding;
import com.sqlihunter.findings.FindingsStore;
import com.sqlihunter.findings.Severity;
import com.sqlihunter.mutation.ParameterLocation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportersTest {

    private Finding sample() {
        return Finding.builder()
                .title("Error-based SQL injection in parameter 'id'")
                .type("Error-based SQL injection")
                .severity(Severity.HIGH)
                .confidence(Confidence.HIGH)
                .host("app.example.com")
                .endpoint("/product")
                .method("GET")
                .paramName("id")
                .paramLocation(ParameterLocation.URL)
                .dbFamily(DbFamily.MYSQL)
                .detectionMethod("Active error-based")
                .evidenceSummary("MySQL syntax error appeared")
                .httpStatus(500)
                .cvssVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N")
                .baselineRequest("GET /product?id=1 HTTP/1.1\r\nCookie: session=secretsession\r\n")
                .testResponse("You have an error in your SQL syntax")
                .build();
    }

    @Test
    void jsonContainsCoreFieldsAndRedacts() {
        String json = new JsonReporter(new Redactor(true)).report(List.of(sample()));
        assertTrue(json.contains("\"type\": \"Error-based SQL injection\""));
        assertTrue(json.contains("A03:2021"));
        assertTrue(json.contains("cvssV4Vector"));
        assertFalse(json.contains("secretsession"), "cookie must be redacted in JSON evidence");
    }

    @Test
    void csvHasHeaderAndRow() {
        String csv = new CsvReporter().report(List.of(sample()));
        assertTrue(csv.startsWith("id,severity,confidence"));
        assertTrue(csv.contains("HIGH"));
        assertTrue(csv.contains("app.example.com"));
    }

    @Test
    void htmlRendersAndRedacts() {
        String html = new HtmlReporter(new Redactor(true)).report(List.of(sample()));
        assertTrue(html.contains("<html"));
        assertTrue(html.contains("Error-based SQL injection"));
        assertFalse(html.contains("secretsession"));
    }

    @Test
    void storeDeduplicatesByEndpointParamType() {
        FindingsStore store = new FindingsStore();
        assertTrue(store.add(sample()));
        assertFalse(store.add(sample()), "identical finding must be deduplicated");
        assertEquals(1, store.size());
    }
}
