package com.sqlihunter.detection;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Configurable catalogue of database error signatures with confidence weights.
 *
 * <p>These signatures are intentionally specific: generic words like "error" or
 * "SQL" are never used on their own, because a database-related string in a
 * response is NOT by itself evidence of injection. Each signature carries a
 * weight (0..1) reflecting how strongly it indicates a real backend SQL error.
 */
public final class SqlErrorSignatures {

    /** A single compiled signature. */
    public static final class Signature {
        private final DbFamily family;
        private final Pattern pattern;
        private final double weight;
        private final String description;

        Signature(DbFamily family, String regex, double weight, String description) {
            this.family = family;
            this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
            this.weight = weight;
            this.description = description;
        }

        public DbFamily family() { return family; }
        public Pattern pattern() { return pattern; }
        public double weight() { return weight; }
        public String description() { return description; }
    }

    /** A signature that matched, with the exact text that triggered it. */
    public static final class Match {
        private final Signature signature;
        private final String matchedText;

        Match(Signature signature, String matchedText) {
            this.signature = signature;
            this.matchedText = matchedText;
        }

        public Signature signature() { return signature; }
        public DbFamily family() { return signature.family; }
        public double weight() { return signature.weight; }
        public String matchedText() { return matchedText; }
        public String description() { return signature.description; }
    }

    private static final List<Signature> SIGNATURES = buildDefaults();

    private SqlErrorSignatures() {
    }

    public static List<Signature> all() {
        return Collections.unmodifiableList(SIGNATURES);
    }

    /**
     * Returns every signature match found in {@code body}. The caller is
     * responsible for baseline comparison: a match present in the baseline too
     * is not evidence of injection.
     */
    public static List<Match> findMatches(String body) {
        List<Match> matches = new ArrayList<>();
        if (body == null || body.isEmpty()) {
            return matches;
        }
        for (Signature sig : SIGNATURES) {
            Matcher m = sig.pattern.matcher(body);
            if (m.find()) {
                matches.add(new Match(sig, truncate(m.group())));
            }
        }
        return matches;
    }

    private static String truncate(String s) {
        s = s.replaceAll("\\s+", " ").trim();
        return s.length() > 200 ? s.substring(0, 200) + "..." : s;
    }

    private static List<Signature> buildDefaults() {
        List<Signature> s = new ArrayList<>();

        // ---- MySQL / MariaDB ----
        s.add(new Signature(DbFamily.MYSQL,
                "You have an error in your SQL syntax;.*?MySQL server version", 0.95,
                "MySQL syntax error with server-version hint"));
        s.add(new Signature(DbFamily.MYSQL,
                "You have an error in your SQL syntax", 0.85, "MySQL syntax error"));
        s.add(new Signature(DbFamily.MYSQL,
                "Warning:\\s+mysqli?(_\\w+)?\\(\\)", 0.8, "PHP mysql/mysqli function warning"));
        s.add(new Signature(DbFamily.MYSQL,
                "check the manual that corresponds to your (MySQL|MariaDB) server version", 0.9,
                "MySQL/MariaDB manual-reference error"));
        s.add(new Signature(DbFamily.MYSQL,
                "com\\.mysql\\.jdbc\\.exceptions|com\\.mysql\\.cj\\.jdbc", 0.85,
                "MySQL JDBC driver exception"));
        s.add(new Signature(DbFamily.MYSQL,
                "MySqlException", 0.8, "MySQL .NET exception"));

        // ---- PostgreSQL ----
        s.add(new Signature(DbFamily.POSTGRESQL,
                "PostgreSQL.*?ERROR:", 0.9, "PostgreSQL ERROR line"));
        s.add(new Signature(DbFamily.POSTGRESQL,
                "pg_query\\(\\)|pg_exec\\(\\)", 0.8, "PHP pg_query/pg_exec warning"));
        s.add(new Signature(DbFamily.POSTGRESQL,
                "org\\.postgresql\\.util\\.PSQLException", 0.85, "PostgreSQL JDBC exception"));
        s.add(new Signature(DbFamily.POSTGRESQL,
                "unterminated quoted string at or near", 0.85, "PostgreSQL unterminated string"));
        s.add(new Signature(DbFamily.POSTGRESQL,
                "syntax error at or near", 0.8, "PostgreSQL syntax error"));

        // ---- Microsoft SQL Server ----
        s.add(new Signature(DbFamily.MSSQL,
                "Unclosed quotation mark after the character string", 0.9,
                "MSSQL unclosed quotation mark"));
        s.add(new Signature(DbFamily.MSSQL,
                "Microsoft SQL Server|Microsoft OLE DB Provider for SQL Server", 0.8,
                "MSSQL provider banner"));
        s.add(new Signature(DbFamily.MSSQL,
                "System\\.Data\\.SqlClient\\.SqlException", 0.85, "MSSQL .NET SqlException"));
        s.add(new Signature(DbFamily.MSSQL,
                "Incorrect syntax near", 0.85, "MSSQL incorrect-syntax error"));
        s.add(new Signature(DbFamily.MSSQL,
                "com\\.microsoft\\.sqlserver\\.jdbc", 0.85, "MSSQL JDBC driver exception"));

        // ---- Oracle ----
        s.add(new Signature(DbFamily.ORACLE,
                "ORA-[0-9]{5}", 0.9, "Oracle ORA-NNNNN error code"));
        s.add(new Signature(DbFamily.ORACLE,
                "Oracle error|Oracle.*?Driver|quoted string not properly terminated", 0.8,
                "Oracle driver/error text"));
        s.add(new Signature(DbFamily.ORACLE,
                "java\\.sql\\.SQLException:.*?ORA-", 0.85, "Oracle JDBC SQLException"));

        // ---- SQLite ----
        s.add(new Signature(DbFamily.SQLITE,
                "SQLite3?::|SQLiteException|sqlite3\\.OperationalError", 0.85, "SQLite exception"));
        s.add(new Signature(DbFamily.SQLITE,
                "unrecognized token:|near \".*?\": syntax error", 0.8, "SQLite tokenizer error"));
        s.add(new Signature(DbFamily.SQLITE,
                "org\\.sqlite\\.JDBC", 0.8, "SQLite JDBC driver"));

        // ---- Generic JDBC / ORM ----
        s.add(new Signature(DbFamily.GENERIC_JDBC,
                "java\\.sql\\.SQLSyntaxErrorException", 0.8, "Generic JDBC syntax exception"));
        s.add(new Signature(DbFamily.GENERIC_JDBC,
                "org\\.hibernate\\.exception\\.SQLGrammarException", 0.8,
                "Hibernate SQL grammar exception"));
        s.add(new Signature(DbFamily.GENERIC_JDBC,
                "javax\\.persistence\\.PersistenceException|jakarta\\.persistence", 0.6,
                "JPA persistence exception (weaker)"));
        s.add(new Signature(DbFamily.GENERIC_JDBC,
                "SQLSTATE\\[[0-9A-Z]{5}\\]", 0.75, "PDO/ODBC SQLSTATE marker"));

        return s;
    }
}
