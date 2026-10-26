package com.sqlihunter.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanConfigTest {

    @Test
    void defaultsAreSafe() {
        ScanConfig c = new ScanConfig();
        assertFalse(c.activeEnabled(), "active off by default");
        assertFalse(c.timeBasedEnabled(), "time-based off by default");
        assertTrue(c.redactReports(), "redaction on by default");
    }

    @Test
    void passiveProfileDisablesActive() {
        ScanConfig c = new ScanConfig();
        c.setActiveEnabled(true);
        c.applyProfile(ScanProfile.PASSIVE_ONLY);
        assertFalse(c.activeEnabled());
        assertFalse(c.timeBasedEnabled());
    }

    @Test
    void lowActiveProfileKeepsTimeBasedOff() {
        ScanConfig c = new ScanConfig();
        c.applyProfile(ScanProfile.LOW_ACTIVE);
        assertTrue(c.activeEnabled());
        assertTrue(c.errorBasedEnabled());
        assertFalse(c.booleanBlindEnabled());
        assertFalse(c.timeBasedEnabled());
    }

    @Test
    void exclusionRulesMatch() {
        ScanConfig c = new ScanConfig();
        assertTrue(c.isParamExcluded("csrf_token"));
        assertTrue(c.isParamExcluded("PASSWORD"));
        assertFalse(c.isParamExcluded("productId"));
        assertTrue(c.isPathExcluded("/account/logout"));
        assertFalse(c.isPathExcluded("/catalog/search"));
    }
}
