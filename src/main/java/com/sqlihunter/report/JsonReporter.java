package com.sqlihunter.report;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sqlihunter.findings.Finding;

import java.util.List;

/** Serialises findings to JSON, applying redaction to evidence fields. */
public final class JsonReporter {

    private final Redactor redactor;

    public JsonReporter(Redactor redactor) {
        this.redactor = redactor;
    }

    public String report(List<Finding> findings) {
        JsonObject root = new JsonObject();
        root.addProperty("tool", "SQLiHunter");
        root.addProperty("owaspCategory", Finding.OWASP_CATEGORY);
        root.addProperty("generatedAt", java.time.Instant.now().toString());
        root.addProperty("findingCount", findings.size());

        JsonArray arr = new JsonArray();
        for (Finding f : findings) {
            arr.add(toJson(f));
        }
        root.add("findings", arr);
        return new GsonBuilder().setPrettyPrinting().create().toJson(root);
    }

    private JsonObject toJson(Finding f) {
        JsonObject o = new JsonObject();
        o.addProperty("id", f.id());
        o.addProperty("timestamp", f.timestamp().toString());
        o.addProperty("title", f.title());
        o.addProperty("type", f.type());
        o.addProperty("severity", f.severity().name());
        o.addProperty("confidence", f.confidence().name());
        o.addProperty("host", f.host());
        o.addProperty("endpoint", f.endpoint());
        o.addProperty("method", f.method());
        o.addProperty("parameter", f.paramName());
        o.addProperty("parameterLocation", f.paramLocation().display());
        o.addProperty("databaseFamily", f.dbFamily().display());
        o.addProperty("detectionMethod", f.detectionMethod());
        o.addProperty("httpStatus", f.httpStatus());
        o.addProperty("owaspCategory", Finding.OWASP_CATEGORY);
        o.addProperty("preconditions", f.preconditions());
        o.addProperty("evidenceSummary", f.evidenceSummary());
        o.addProperty("limitations", f.limitations());
        if (f.cvssVector() != null) {
            o.addProperty("cvssV4Vector", f.cvssVector());
        }
        o.addProperty("remediation", f.remediation());

        JsonArray steps = new JsonArray();
        f.reproSteps().forEach(steps::add);
        o.add("reproductionSteps", steps);

        JsonArray refs = new JsonArray();
        f.references().forEach(refs::add);
        o.add("references", refs);

        JsonObject ev = new JsonObject();
        ev.addProperty("baselineRequest", redactor.apply(f.baselineRequest()));
        ev.addProperty("baselineResponse", redactor.apply(f.baselineResponse()));
        ev.addProperty("testRequest", redactor.apply(f.testRequest()));
        ev.addProperty("testResponse", redactor.apply(f.testResponse()));
        o.add("evidence", ev);
        return o;
    }
}
