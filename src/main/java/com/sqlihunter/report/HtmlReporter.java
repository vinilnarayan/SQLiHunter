package com.sqlihunter.report;

import com.sqlihunter.findings.Finding;

import java.util.List;

/** Produces a self-contained, human-readable HTML report. */
public final class HtmlReporter {

    private final Redactor redactor;

    public HtmlReporter(Redactor redactor) {
        this.redactor = redactor;
    }

    public String report(List<Finding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        sb.append("<title>SQLiHunter Report</title>");
        sb.append("<style>")
          .append("body{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:2rem;color:#1b1b1b;}")
          .append("h1{margin-bottom:0;}small{color:#666;}")
          .append("table{border-collapse:collapse;width:100%;margin:1rem 0;}")
          .append("th,td{border:1px solid #ddd;padding:6px 8px;font-size:13px;text-align:left;vertical-align:top;}")
          .append("th{background:#f4f4f4;}")
          .append(".sev-HIGH{color:#fff;background:#c0392b;}.sev-MEDIUM{background:#e67e22;color:#fff;}")
          .append(".sev-LOW{background:#f1c40f;}.sev-INFORMATIONAL{background:#95a5a6;color:#fff;}.sev-CRITICAL{background:#6c1414;color:#fff;}")
          .append(".badge{padding:2px 6px;border-radius:3px;font-weight:600;font-size:12px;}")
          .append(".finding{border:1px solid #ddd;border-radius:6px;padding:1rem;margin:1rem 0;}")
          .append("pre{background:#111;color:#e6e6e6;padding:10px;border-radius:4px;overflow:auto;max-height:320px;font-size:12px;}")
          .append(".meta{display:grid;grid-template-columns:200px 1fr;gap:4px 12px;font-size:13px;}")
          .append(".meta div:nth-child(odd){color:#555;font-weight:600;}")
          .append("</style></head><body>");

        sb.append("<h1>SQLiHunter Report</h1>");
        sb.append("<small>Generated ").append(esc(java.time.Instant.now().toString()))
          .append(" &middot; ").append(findings.size()).append(" finding(s) &middot; OWASP ")
          .append(esc(Finding.OWASP_CATEGORY)).append("</small>");
        sb.append("<p>SQLiHunter findings are evidence-backed but automated. Validate before "
                + "reporting externally. CRITICAL and CONFIRMED classifications require manual escalation.</p>");

        // summary table
        sb.append("<h2>Summary</h2><table><tr><th>Severity</th><th>Confidence</th><th>Type</th>"
                + "<th>Method</th><th>Endpoint</th><th>Parameter</th><th>DB</th></tr>");
        for (Finding f : findings) {
            sb.append("<tr>")
              .append("<td><span class=\"badge sev-").append(f.severity().name()).append("\">")
              .append(f.severity().name()).append("</span></td>")
              .append("<td>").append(f.confidence().name()).append("</td>")
              .append("<td>").append(esc(f.type())).append("</td>")
              .append("<td>").append(esc(f.method())).append("</td>")
              .append("<td>").append(esc(f.host())).append(esc(f.endpoint())).append("</td>")
              .append("<td>").append(esc(f.paramName())).append(" <em>(").append(esc(f.paramLocation().display())).append(")</em></td>")
              .append("<td>").append(esc(f.dbFamily().display())).append("</td>")
              .append("</tr>");
        }
        sb.append("</table>");

        // detail
        sb.append("<h2>Findings</h2>");
        int n = 1;
        for (Finding f : findings) {
            sb.append("<div class=\"finding\">");
            sb.append("<h3>").append(n++).append(". ").append(esc(f.title())).append("</h3>");
            sb.append("<div class=\"meta\">");
            meta(sb, "Severity", f.severity().name());
            meta(sb, "Confidence", f.confidence().name());
            meta(sb, "Type", f.type());
            meta(sb, "Endpoint", f.method() + " " + f.host() + f.endpoint());
            meta(sb, "Parameter", f.paramName() + " (" + f.paramLocation().display() + ")");
            meta(sb, "Database", f.dbFamily().display());
            meta(sb, "HTTP status", Integer.toString(f.httpStatus()));
            meta(sb, "Detection method", f.detectionMethod());
            meta(sb, "OWASP", Finding.OWASP_CATEGORY);
            if (f.cvssVector() != null) {
                meta(sb, "CVSS v4.0", f.cvssVector());
            }
            sb.append("</div>");

            section(sb, "Preconditions", f.preconditions());
            section(sb, "Evidence summary", f.evidenceSummary());
            section(sb, "Confidence & limitations", f.limitations());

            sb.append("<h4>Steps to reproduce</h4><ol>");
            for (String s : f.reproSteps()) {
                sb.append("<li>").append(esc(s)).append("</li>");
            }
            sb.append("</ol>");

            pre(sb, "Baseline request", redactor.apply(f.baselineRequest()));
            pre(sb, "Baseline response", redactor.apply(f.baselineResponse()));
            pre(sb, "Test request", redactor.apply(f.testRequest()));
            pre(sb, "Test response", redactor.apply(f.testResponse()));

            section(sb, "Remediation", f.remediation());
            sb.append("<h4>References</h4><ul>");
            for (String r : f.references()) {
                sb.append("<li>").append(esc(r)).append("</li>");
            }
            sb.append("</ul>");
            sb.append("</div>");
        }

        sb.append("</body></html>");
        return sb.toString();
    }

    private void meta(StringBuilder sb, String k, String v) {
        sb.append("<div>").append(esc(k)).append("</div><div>").append(esc(v)).append("</div>");
    }

    private void section(StringBuilder sb, String title, String body) {
        if (body == null || body.isEmpty()) {
            return;
        }
        sb.append("<h4>").append(esc(title)).append("</h4><p>")
          .append(esc(body).replace("\n", "<br>")).append("</p>");
    }

    private void pre(StringBuilder sb, String title, String body) {
        if (body == null || body.isEmpty()) {
            return;
        }
        sb.append("<h4>").append(esc(title)).append("</h4><pre>").append(esc(body)).append("</pre>");
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
