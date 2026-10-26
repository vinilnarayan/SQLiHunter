package com.sqlihunter.detection;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SqlErrorSignaturesTest {

    @Test
    void detectsMySqlSyntaxError() {
        String body = "You have an error in your SQL syntax; check the manual that corresponds "
                + "to your MySQL server version for the right syntax to use near ''' at line 1";
        List<SqlErrorSignatures.Match> m = SqlErrorSignatures.findMatches(body);
        assertFalse(m.isEmpty());
        assertTrue(m.stream().anyMatch(x -> x.family() == DbFamily.MYSQL));
    }

    @Test
    void detectsOraCode() {
        List<SqlErrorSignatures.Match> m = SqlErrorSignatures.findMatches("... ORA-01756: quoted string ...");
        assertTrue(m.stream().anyMatch(x -> x.family() == DbFamily.ORACLE));
    }

    @Test
    void benignTextWithWordSqlDoesNotMatch() {
        // Requirement: do not flag just because a DB-related word appears.
        String body = "<p>Learn SQL and database design in our new error-free tutorial.</p>";
        assertTrue(SqlErrorSignatures.findMatches(body).isEmpty(),
                "generic DB vocabulary must not match any signature");
    }

    @Test
    void emptyBodyNoMatches() {
        assertEquals(0, SqlErrorSignatures.findMatches("").size());
        assertEquals(0, SqlErrorSignatures.findMatches(null).size());
    }
}
