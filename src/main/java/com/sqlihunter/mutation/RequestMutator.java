package com.sqlihunter.mutation;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Parses a Burp request into testable inputs and builds mutated copies with a
 * single input changed, preserving everything else (method, URL, other params,
 * headers, cookies, content type, multipart boundaries).
 *
 * <p>All mutated requests are produced via Montoya's immutable
 * {@code withUpdatedParameters}/{@code withBody}/{@code withUpdatedHeader}/
 * {@code withPath} builders, so Content-Length and structure stay consistent.
 * The original request is never modified and is kept by callers as the baseline.
 */
public final class RequestMutator {

    /** Result of parameter discovery, including inputs that were skipped. */
    public static final class Discovery {
        public final List<Param> params;
        public final List<String> warnings;

        Discovery(List<Param> params, List<String> warnings) {
            this.params = params;
            this.warnings = warnings;
        }
    }

    /**
     * Discovers eligible parameters.
     *
     * @param includeHeaders when true, the named headers (if present) are offered
     * @param headerNames    header names eligible for testing (e.g. User-Agent)
     * @param includePath    when true, path segments are offered as inputs
     */
    public Discovery discover(HttpRequest request, boolean includeHeaders,
                              List<String> headerNames, boolean includePath) {
        List<Param> params = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        // Native Burp-parsed parameters: URL, BODY (form), COOKIE, XML, MULTIPART.
        Map<String, Integer> nameTypeCount = new LinkedHashMap<>();
        for (ParsedHttpParameter p : request.parameters()) {
            String ck = p.type().name() + ":" + p.name();
            nameTypeCount.merge(ck, 1, Integer::sum);
        }
        for (ParsedHttpParameter p : request.parameters()) {
            HttpParameterType type = p.type();
            if (type == HttpParameterType.JSON) {
                // Handled below with full nested-pointer support.
                continue;
            }
            ParameterLocation loc = ParameterLocation.fromMontoya(type);
            String ck = type.name() + ":" + p.name();
            if (!seen.add(ck)) {
                continue; // duplicate (name,type) already queued
            }
            if (nameTypeCount.getOrDefault(ck, 1) > 1) {
                warnings.add("Parameter '" + p.name() + "' (" + loc.display()
                        + ") appears multiple times; mutation updates all occurrences together.");
            }
            String logical = (loc == ParameterLocation.URL || loc == ParameterLocation.BODY)
                    ? urlDecode(p.value()) : p.value();
            params.add(new Param(p.name(), logical, loc));
        }

        // JSON body: nested pointers via Gson.
        String body = request.bodyToString();
        if (JsonSupport.looksLikeJson(body)) {
            Map<String, String> leaves = JsonSupport.enumerateLeaves(body);
            if (leaves.isEmpty()) {
                warnings.add("Body looks like JSON but no string/number leaves could be parsed; skipped.");
            }
            for (Map.Entry<String, String> e : leaves.entrySet()) {
                params.add(new Param(e.getKey(), e.getValue(), ParameterLocation.JSON));
            }
        } else if (!body.isEmpty() && request.parameters().isEmpty()) {
            warnings.add("Request has a body that is neither form-encoded nor JSON; "
                    + "no parameters parsed (XML/custom formats may need manual testing).");
        }

        // Headers (opt-in).
        if (includeHeaders && headerNames != null) {
            for (String h : headerNames) {
                String val = request.headerValue(h);
                if (val != null) {
                    params.add(new Param(h, val, ParameterLocation.HEADER));
                }
            }
        }

        // Path segments (opt-in).
        if (includePath) {
            String path = request.pathWithoutQuery();
            String[] segs = path.split("/");
            for (int i = 0; i < segs.length; i++) {
                if (!segs[i].isEmpty()) {
                    params.add(new Param(Integer.toString(i), urlDecode(segs[i]), ParameterLocation.PATH));
                }
            }
        }

        return new Discovery(params, warnings);
    }

    /**
     * Builds a mutated request where {@code param} carries {@code logicalValue}
     * (the decoded/plain value). Encoding appropriate to the location is applied
     * here so payloads are never corrupted. Returns null if the mutation cannot
     * be applied safely (e.g. a JSON pointer that no longer resolves).
     */
    public HttpRequest mutate(HttpRequest original, Param param, String logicalValue) {
        switch (param.location()) {
            case URL:
                return original.withUpdatedParameters(
                        HttpParameter.parameter(param.name(), urlEncode(logicalValue), HttpParameterType.URL));
            case BODY:
                return original.withUpdatedParameters(
                        HttpParameter.parameter(param.name(), urlEncode(logicalValue), HttpParameterType.BODY));
            case COOKIE:
                return original.withUpdatedParameters(
                        HttpParameter.parameter(param.name(), urlEncode(logicalValue), HttpParameterType.COOKIE));
            case XML:
                return original.withUpdatedParameters(
                        HttpParameter.parameter(param.name(), xmlEscape(logicalValue), HttpParameterType.XML));
            case MULTIPART:
                return original.withUpdatedParameters(
                        HttpParameter.parameter(param.name(), logicalValue, HttpParameterType.MULTIPART_ATTRIBUTE));
            case JSON: {
                String newBody = JsonSupport.setLeaf(original.bodyToString(), param.name(), logicalValue);
                if (newBody == null) {
                    return null;
                }
                return original.withBody(newBody);
            }
            case HEADER:
                return original.withUpdatedHeader(param.name(), stripCrLf(logicalValue));
            case PATH: {
                String target = rebuildPath(original, Integer.parseInt(param.name()), logicalValue);
                if (target == null) {
                    return null;
                }
                return original.withPath(target);
            }
            default:
                return null;
        }
    }

    private String rebuildPath(HttpRequest original, int segmentIndex, String logicalValue) {
        String path = original.pathWithoutQuery();
        String[] segs = path.split("/", -1);
        if (segmentIndex < 0 || segmentIndex >= segs.length) {
            return null;
        }
        segs[segmentIndex] = pathEncode(logicalValue);
        String rebuilt = String.join("/", segs);
        String query = original.query();
        return (query == null || query.isEmpty()) ? rebuilt : rebuilt + "?" + query;
    }

    // ---- encoding helpers ----

    static String urlEncode(String s) {
        try {
            return URLEncoder.encode(s, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            return s; // UTF-8 always supported
        }
    }

    static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8.name());
        } catch (IllegalArgumentException | UnsupportedEncodingException e) {
            return s; // malformed %xx: leave as-is rather than corrupt
        }
    }

    static String pathEncode(String s) {
        // Encode space and reserved chars but keep the segment readable.
        return urlEncode(s).replace("+", "%20");
    }

    static String xmlEscape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }

    static String stripCrLf(String s) {
        return s.replace("\r", "").replace("\n", "");
    }
}
