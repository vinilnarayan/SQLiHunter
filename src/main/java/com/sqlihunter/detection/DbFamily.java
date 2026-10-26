package com.sqlihunter.detection;

/** Database families recognised by the signature engine and fingerprinter. */
public enum DbFamily {
    MYSQL("MySQL/MariaDB"),
    POSTGRESQL("PostgreSQL"),
    MSSQL("Microsoft SQL Server"),
    ORACLE("Oracle"),
    SQLITE("SQLite"),
    GENERIC_JDBC("Generic JDBC/ORM"),
    UNKNOWN("Unknown");

    private final String display;

    DbFamily(String display) {
        this.display = display;
    }

    public String display() {
        return display;
    }
}
