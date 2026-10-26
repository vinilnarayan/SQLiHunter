package com.sqlihunter.mutation;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * JSON body support for the mutation engine. Enumerates leaf values as
 * JSON-Pointer-style paths ({@code /user/id}, {@code /items/0/sku}) and sets a
 * leaf by path without disturbing the rest of the document. Arrays and nested
 * objects are preserved. Uses Gson (bundled, relocated at build time).
 */
public final class JsonSupport {

    // disableHtmlEscaping so injected payloads (', ", =, <, >) appear literally in
    // the mutated body and in evidence, rather than as unicode-escaped sequences.
    // Both forms decode identically server-side, but literal text is clearer.
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    private JsonSupport() {
    }

    public static boolean looksLikeJson(String body) {
        if (body == null) {
            return false;
        }
        String t = body.trim();
        return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
    }

    /** Map of JSON pointer -> current leaf value (string form) for string/number leaves. */
    public static Map<String, String> enumerateLeaves(String body) {
        Map<String, String> leaves = new LinkedHashMap<>();
        try {
            JsonElement root = JsonParser.parseString(body);
            walk("", root, leaves);
        } catch (RuntimeException ex) {
            // Not valid JSON; caller treats this as "unparseable".
        }
        return leaves;
    }

    private static void walk(String prefix, JsonElement el, Map<String, String> out) {
        if (el.isJsonObject()) {
            JsonObject obj = el.getAsJsonObject();
            for (Map.Entry<String, JsonElement> e : obj.entrySet()) {
                walk(prefix + "/" + escape(e.getKey()), e.getValue(), out);
            }
        } else if (el.isJsonArray()) {
            JsonArray arr = el.getAsJsonArray();
            for (int i = 0; i < arr.size(); i++) {
                walk(prefix + "/" + i, arr.get(i), out);
            }
        } else if (el.isJsonPrimitive()) {
            JsonPrimitive p = el.getAsJsonPrimitive();
            // Only string and number leaves are useful injection points.
            if (p.isString() || p.isNumber()) {
                out.put(prefix, p.getAsString());
            }
        }
    }

    /**
     * Returns a new JSON body string with the leaf at {@code pointer} set to the
     * given string value (written as a JSON string). Returns null if the pointer
     * cannot be resolved or the body is not valid JSON.
     */
    public static String setLeaf(String body, String pointer, String value) {
        try {
            JsonElement root = JsonParser.parseString(body);
            List<String> parts = parsePointer(pointer);
            if (parts.isEmpty()) {
                return null;
            }
            JsonElement cursor = root;
            for (int i = 0; i < parts.size() - 1; i++) {
                cursor = step(cursor, parts.get(i));
                if (cursor == null) {
                    return null;
                }
            }
            String last = parts.get(parts.size() - 1);
            if (cursor.isJsonObject()) {
                cursor.getAsJsonObject().add(last, new JsonPrimitive(value));
            } else if (cursor.isJsonArray()) {
                int idx = Integer.parseInt(last);
                JsonArray arr = cursor.getAsJsonArray();
                if (idx < 0 || idx >= arr.size()) {
                    return null;
                }
                arr.set(idx, new JsonPrimitive(value));
            } else {
                return null;
            }
            return GSON.toJson(root);
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private static JsonElement step(JsonElement cursor, String part) {
        if (cursor.isJsonObject()) {
            return cursor.getAsJsonObject().get(part);
        }
        if (cursor.isJsonArray()) {
            try {
                return cursor.getAsJsonArray().get(Integer.parseInt(part));
            } catch (NumberFormatException | IndexOutOfBoundsException e) {
                return null;
            }
        }
        return null;
    }

    private static List<String> parsePointer(String pointer) {
        List<String> parts = new ArrayList<>();
        for (String raw : pointer.split("/")) {
            if (!raw.isEmpty()) {
                parts.add(unescape(raw));
            }
        }
        return parts;
    }

    // RFC 6901 token escaping (~ and /).
    private static String escape(String s) {
        return s.replace("~", "~0").replace("/", "~1");
    }

    private static String unescape(String s) {
        return s.replace("~1", "/").replace("~0", "~");
    }
}
