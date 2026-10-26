package com.sqlihunter.core;

/** Preset intensity profiles. All active profiles still obey scope, budget and rate limits. */
public enum ScanProfile {
    /** No traffic generated; analyse captured request/response only. */
    PASSIVE_ONLY,
    /** Minimal active probing: error-based only, tiny budget. */
    LOW_ACTIVE,
    /** Error-based + boolean-blind with standard budgets. Time-based stays off. */
    STANDARD_ACTIVE,
    /** Fully tester-defined; nothing is forced on or off. */
    CUSTOM;
}
