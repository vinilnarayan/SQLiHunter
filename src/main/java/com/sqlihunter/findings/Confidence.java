package com.sqlihunter.findings;

/**
 * Confidence classification for a finding. "CONFIRMED" is never set by the
 * automated engine; it exists so a tester can manually promote a finding after
 * independent verification.
 */
public enum Confidence {
    POTENTIAL,
    LOW,
    MEDIUM,
    HIGH,
    CONFIRMED;
}
