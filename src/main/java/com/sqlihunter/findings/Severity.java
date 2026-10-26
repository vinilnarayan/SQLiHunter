package com.sqlihunter.findings;

/**
 * Finding severity. Deliberately conservative: CRITICAL is never assigned
 * automatically by the engine (see {@code ScanEngine}); it is reserved for
 * manual escalation after a tester demonstrates severe impact.
 */
public enum Severity {
    INFORMATIONAL,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;
}
