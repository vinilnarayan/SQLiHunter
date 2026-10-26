package com.sqlihunter.detection;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Estimates the database family from error-signature evidence only. Purely
 * passive over text already obtained; it never issues invasive version queries.
 * Returns {@link DbFamily#UNKNOWN} when evidence is weak or contradictory.
 */
public final class DatabaseFingerprinter {

    public static final class Result {
        public final DbFamily family;
        public final double confidence; // 0..1
        public final String evidence;

        Result(DbFamily family, double confidence, String evidence) {
            this.family = family;
            this.confidence = confidence;
            this.evidence = evidence;
        }
    }

    private DatabaseFingerprinter() {
    }

    public static Result fingerprint(List<SqlErrorSignatures.Match> matches) {
        if (matches == null || matches.isEmpty()) {
            return new Result(DbFamily.UNKNOWN, 0.0, "No database error signatures matched.");
        }
        // Sum weights per family; strongest wins, but require a clear margin.
        Map<DbFamily, Double> scores = new TreeMap<>();
        StringBuilder evidence = new StringBuilder();
        for (SqlErrorSignatures.Match m : matches) {
            if (m.family() == DbFamily.GENERIC_JDBC) {
                continue; // generic doesn't identify a specific family
            }
            scores.merge(m.family(), m.weight(), Double::sum);
            evidence.append("- ").append(m.family().display())
                    .append(": \"").append(m.matchedText()).append("\"\n");
        }
        if (scores.isEmpty()) {
            return new Result(DbFamily.GENERIC_JDBC, 0.4,
                    "Generic JDBC/ORM exception without a family-specific marker.");
        }
        DbFamily best = null;
        double bestScore = 0;
        double secondScore = 0;
        for (Map.Entry<DbFamily, Double> e : scores.entrySet()) {
            if (e.getValue() > bestScore) {
                secondScore = bestScore;
                bestScore = e.getValue();
                best = e.getKey();
            } else if (e.getValue() > secondScore) {
                secondScore = e.getValue();
            }
        }
        // Require the top family to clearly dominate; otherwise stay UNKNOWN.
        if (best == null || bestScore - secondScore < 0.3) {
            return new Result(DbFamily.UNKNOWN, 0.3,
                    "Conflicting database signatures; family not determined.\n" + evidence);
        }
        double confidence = Math.min(1.0, bestScore / 2.0);
        return new Result(best, confidence, evidence.toString().trim());
    }
}
