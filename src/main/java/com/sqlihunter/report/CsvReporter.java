package com.sqlihunter.report;

import com.sqlihunter.findings.Finding;

import java.util.List;

/** Serialises findings to CSV (summary columns; full evidence lives in JSON/HTML). */
public final class CsvReporter {

    private static final String[] HEADERS = {
            "id", "severity", "confidence", "type", "method", "host", "endpoint",
            "parameter", "location", "databaseFamily", "httpStatus", "detectionMethod",
            "owaspCategory", "cvssV4Vector", "title"
    };

    public String report(List<Finding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.join(",", HEADERS)).append("\r\n");
        for (Finding f : findings) {
            append(sb, f.id());
            append(sb, f.severity().name());
            append(sb, f.confidence().name());
            append(sb, f.type());
            append(sb, f.method());
            append(sb, f.host());
            append(sb, f.endpoint());
            append(sb, f.paramName());
            append(sb, f.paramLocation().display());
            append(sb, f.dbFamily().display());
            append(sb, Integer.toString(f.httpStatus()));
            append(sb, f.detectionMethod());
            append(sb, Finding.OWASP_CATEGORY);
            append(sb, f.cvssVector() == null ? "" : f.cvssVector());
            appendLast(sb, f.title());
        }
        return sb.toString();
    }

    private void append(StringBuilder sb, String v) {
        sb.append(escape(v)).append(',');
    }

    private void appendLast(StringBuilder sb, String v) {
        sb.append(escape(v)).append("\r\n");
    }

    private String escape(String v) {
        if (v == null) {
            return "";
        }
        String s = v.replace("\"", "\"\"");
        return "\"" + s + "\"";
    }
}
