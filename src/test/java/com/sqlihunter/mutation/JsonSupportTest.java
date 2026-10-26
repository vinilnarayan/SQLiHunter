package com.sqlihunter.mutation;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonSupportTest {

    @Test
    void enumeratesNestedLeaves() {
        String body = "{\"user\":{\"id\":5,\"name\":\"bob\"},\"items\":[{\"sku\":\"A1\"},{\"sku\":\"B2\"}]}";
        Map<String, String> leaves = JsonSupport.enumerateLeaves(body);
        assertEquals("5", leaves.get("/user/id"));
        assertEquals("bob", leaves.get("/user/name"));
        assertEquals("A1", leaves.get("/items/0/sku"));
        assertEquals("B2", leaves.get("/items/1/sku"));
    }

    @Test
    void setLeafPreservesSiblingsAndNesting() {
        String body = "{\"user\":{\"id\":5,\"name\":\"bob\"}}";
        String out = JsonSupport.setLeaf(body, "/user/id", "5' OR '1'='1");
        assertTrue(out.contains("\"name\":\"bob\""), "sibling preserved");
        assertTrue(out.contains("5' OR '1'='1"), "injected value present (escaped by Gson)");
    }

    @Test
    void setLeafInArray() {
        String body = "{\"items\":[{\"sku\":\"A1\"},{\"sku\":\"B2\"}]}";
        String out = JsonSupport.setLeaf(body, "/items/1/sku", "X");
        assertTrue(out.contains("\"A1\""));
        assertTrue(out.contains("\"X\""));
        assertFalse(out.contains("\"B2\""));
    }

    @Test
    void unresolvablePointerReturnsNull() {
        assertNull(JsonSupport.setLeaf("{\"a\":1}", "/does/not/exist", "x"));
    }

    @Test
    void invalidJsonReportsNoLeaves() {
        assertTrue(JsonSupport.enumerateLeaves("not json").isEmpty());
        assertFalse(JsonSupport.looksLikeJson("not json"));
        assertTrue(JsonSupport.looksLikeJson("{\"a\":1}"));
    }
}
