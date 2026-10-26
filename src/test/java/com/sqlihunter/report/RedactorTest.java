package com.sqlihunter.report;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RedactorTest {

    @Test
    void redactsAuthCookieAndTokens() {
        String text = "GET / HTTP/1.1\r\n"
                + "Authorization: Bearer secrettokenvalue\r\n"
                + "Cookie: session=abcdef12345\r\n"
                + "\r\n"
                + "{\"password\":\"p@ssw0rd\",\"api_key\":\"KEY123\"}";
        String out = new Redactor(true).apply(text);
        assertFalse(out.contains("secrettokenvalue"));
        assertFalse(out.contains("abcdef12345"));
        assertFalse(out.contains("p@ssw0rd"));
        assertFalse(out.contains("KEY123"));
        assertTrue(out.contains("REDACTED"));
    }

    @Test
    void disabledRedactorPassesThrough() {
        String text = "Authorization: Bearer keep";
        assertTrue(new Redactor(false).apply(text).contains("keep"));
    }
}
