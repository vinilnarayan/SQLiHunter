package com.sqlihunter.findings;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.sqlihunter.detection.DbFamily;
import com.sqlihunter.mutation.ParameterLocation;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * An immutable SQL-injection finding with all evidence required for the report.
 * Evidence request/response snippets are stored verbatim; redaction is applied
 * only at export time (see {@code report.Redactor}) so the live UI can show the
 * tester exactly what was sent while saved reports can omit secrets.
 */
public final class Finding {

    public static final String OWASP_CATEGORY = "A03:2021 - Injection";

    private final String id;
    private final Instant timestamp;
    private final String title;
    private final String type;
    private final Severity severity;
    private final Confidence confidence;
    private final String host;
    private final String endpoint;
    private final String method;
    private final String paramName;
    private final ParameterLocation paramLocation;
    private final DbFamily dbFamily;
    private final String detectionMethod;
    private final String evidenceSummary;
    private final int httpStatus;
    private final String remediation;
    private final String preconditions;
    private final String limitations;
    private final String cvssVector; // nullable
    private final List<String> reproSteps;
    private final List<String> references;
    private final String baselineRequest;
    private final String baselineResponse;
    private final String testRequest;
    private final String testResponse;
    private final List<RepeaterEntry> repeaterEntries;

    /**
     * A concrete request from the scan that the tester can push to Burp Repeater
     * for manual confirmation (e.g. the baseline, or the TRUE/FALSE variants).
     * Holds the live immutable {@link HttpRequest}, not just evidence text.
     */
    public static final class RepeaterEntry {
        private final String label;
        private final HttpRequest request;

        public RepeaterEntry(String label, HttpRequest request) {
            this.label = label;
            this.request = request;
        }

        public String label() { return label; }
        public HttpRequest request() { return request; }
    }

    private Finding(Builder b) {
        this.id = b.id;
        this.timestamp = b.timestamp;
        this.title = b.title;
        this.type = b.type;
        this.severity = b.severity;
        this.confidence = b.confidence;
        this.host = b.host;
        this.endpoint = b.endpoint;
        this.method = b.method;
        this.paramName = b.paramName;
        this.paramLocation = b.paramLocation;
        this.dbFamily = b.dbFamily;
        this.detectionMethod = b.detectionMethod;
        this.evidenceSummary = b.evidenceSummary;
        this.httpStatus = b.httpStatus;
        this.remediation = b.remediation;
        this.preconditions = b.preconditions;
        this.limitations = b.limitations;
        this.cvssVector = b.cvssVector;
        this.reproSteps = Collections.unmodifiableList(new ArrayList<>(b.reproSteps));
        this.references = Collections.unmodifiableList(new ArrayList<>(b.references));
        this.baselineRequest = b.baselineRequest;
        this.baselineResponse = b.baselineResponse;
        this.testRequest = b.testRequest;
        this.testResponse = b.testResponse;
        this.repeaterEntries = Collections.unmodifiableList(new ArrayList<>(b.repeaterEntries));
    }

    /** Dedup key: endpoint + parameter + detection type. */
    public String dedupKey() {
        return method + " " + host + endpoint + " | " + paramLocation.name() + ":" + paramName + " | " + type;
    }

    public String id() { return id; }
    public Instant timestamp() { return timestamp; }
    public String title() { return title; }
    public String type() { return type; }
    public Severity severity() { return severity; }
    public Confidence confidence() { return confidence; }
    public String host() { return host; }
    public String endpoint() { return endpoint; }
    public String method() { return method; }
    public String paramName() { return paramName; }
    public ParameterLocation paramLocation() { return paramLocation; }
    public DbFamily dbFamily() { return dbFamily; }
    public String detectionMethod() { return detectionMethod; }
    public String evidenceSummary() { return evidenceSummary; }
    public int httpStatus() { return httpStatus; }
    public String remediation() { return remediation; }
    public String preconditions() { return preconditions; }
    public String limitations() { return limitations; }
    public String cvssVector() { return cvssVector; }
    public List<String> reproSteps() { return reproSteps; }
    public List<String> references() { return references; }
    public String baselineRequest() { return baselineRequest; }
    public String baselineResponse() { return baselineResponse; }
    public String testRequest() { return testRequest; }
    public String testResponse() { return testResponse; }
    public List<RepeaterEntry> repeaterEntries() { return repeaterEntries; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String id = UUID.randomUUID().toString();
        private Instant timestamp = Instant.now();
        private String title = "";
        private String type = "";
        private Severity severity = Severity.INFORMATIONAL;
        private Confidence confidence = Confidence.POTENTIAL;
        private String host = "";
        private String endpoint = "";
        private String method = "";
        private String paramName = "";
        private ParameterLocation paramLocation = ParameterLocation.BODY;
        private DbFamily dbFamily = DbFamily.UNKNOWN;
        private String detectionMethod = "";
        private String evidenceSummary = "";
        private int httpStatus = 0;
        private String remediation = DEFAULT_REMEDIATION;
        private String preconditions = "The tester is authorised to assess the target and the request reaches a code path that builds a SQL query.";
        private String limitations = "";
        private String cvssVector = null;
        private final List<String> reproSteps = new ArrayList<>();
        private final List<String> references = new ArrayList<>(DEFAULT_REFERENCES);
        private String baselineRequest = "";
        private String baselineResponse = "";
        private String testRequest = "";
        private String testResponse = "";
        private final List<RepeaterEntry> repeaterEntries = new ArrayList<>();

        public Builder title(String v) { this.title = v; return this; }
        public Builder type(String v) { this.type = v; return this; }
        public Builder severity(Severity v) { this.severity = v; return this; }
        public Builder confidence(Confidence v) { this.confidence = v; return this; }
        public Builder host(String v) { this.host = v; return this; }
        public Builder endpoint(String v) { this.endpoint = v; return this; }
        public Builder method(String v) { this.method = v; return this; }
        public Builder paramName(String v) { this.paramName = v; return this; }
        public Builder paramLocation(ParameterLocation v) { this.paramLocation = v; return this; }
        public Builder dbFamily(DbFamily v) { this.dbFamily = v; return this; }
        public Builder detectionMethod(String v) { this.detectionMethod = v; return this; }
        public Builder evidenceSummary(String v) { this.evidenceSummary = v; return this; }
        public Builder httpStatus(int v) { this.httpStatus = v; return this; }
        public Builder remediation(String v) { this.remediation = v; return this; }
        public Builder preconditions(String v) { this.preconditions = v; return this; }
        public Builder limitations(String v) { this.limitations = v; return this; }
        public Builder cvssVector(String v) { this.cvssVector = v; return this; }
        public Builder reproStep(String v) { this.reproSteps.add(v); return this; }
        public Builder reference(String v) { this.references.add(v); return this; }
        /** Attach a concrete request that can be sent to Repeater. Null requests are ignored. */
        public Builder repeaterEntry(String label, HttpRequest request) {
            if (request != null) {
                this.repeaterEntries.add(new RepeaterEntry(label, request));
            }
            return this;
        }
        public Builder baselineRequest(String v) { this.baselineRequest = v; return this; }
        public Builder baselineResponse(String v) { this.baselineResponse = v; return this; }
        public Builder testRequest(String v) { this.testRequest = v; return this; }
        public Builder testResponse(String v) { this.testResponse = v; return this; }

        public Finding build() {
            return new Finding(this);
        }
    }

    private static final String DEFAULT_REMEDIATION =
            "Use parameterised queries / prepared statements for all database access. "
            + "Never build SQL by concatenating untrusted input. Apply strict input "
            + "validation (allow-lists) and least-privilege database accounts, and return "
            + "generic error messages so database errors are not exposed to clients.";

    private static final List<String> DEFAULT_REFERENCES = List.of(
            "OWASP Top 10:2021 A03 Injection - https://owasp.org/Top10/A03_2021-Injection/",
            "OWASP SQL Injection Prevention Cheat Sheet - "
                    + "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command - "
                    + "https://cwe.mitre.org/data/definitions/89.html");
}
