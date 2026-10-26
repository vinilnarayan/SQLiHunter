package com.sqlihunter.detection;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DatabaseFingerprinterTest {

    @Test
    void unknownWhenNoEvidence() {
        assertEquals(DbFamily.UNKNOWN, DatabaseFingerprinter.fingerprint(List.of()).family);
    }

    @Test
    void identifiesDominantFamily() {
        List<SqlErrorSignatures.Match> m = SqlErrorSignatures.findMatches(
                "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version");
        DatabaseFingerprinter.Result r = DatabaseFingerprinter.fingerprint(m);
        assertEquals(DbFamily.MYSQL, r.family);
    }

    @Test
    void conflictingEvidenceStaysUnknown() {
        // Craft a body that triggers two different families with comparable weight.
        String body = "Incorrect syntax near ')'. ORA-00933: SQL command not properly ended";
        List<SqlErrorSignatures.Match> m = SqlErrorSignatures.findMatches(body);
        DatabaseFingerprinter.Result r = DatabaseFingerprinter.fingerprint(m);
        assertEquals(DbFamily.UNKNOWN, r.family, "ambiguous evidence must not force a family");
    }
}
