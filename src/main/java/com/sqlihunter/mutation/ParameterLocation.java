package com.sqlihunter.mutation;

import burp.api.montoya.http.message.params.HttpParameterType;

/**
 * Where an injectable input lives in a request. Maps onto Montoya's
 * {@link HttpParameterType} for the types Burp parses natively, plus locations
 * SQLiHunter mutates itself (JSON pointers, path segments, raw headers).
 */
public enum ParameterLocation {
    URL("URL query"),
    BODY("Body (form-urlencoded)"),
    COOKIE("Cookie"),
    JSON("JSON body"),
    XML("XML body"),
    MULTIPART("Multipart field"),
    HEADER("Header"),
    PATH("Path segment");

    private final String display;

    ParameterLocation(String display) {
        this.display = display;
    }

    public String display() {
        return display;
    }

    /** Montoya native type, or {@code null} for locations SQLiHunter mutates directly. */
    public HttpParameterType montoyaType() {
        switch (this) {
            case URL:
                return HttpParameterType.URL;
            case BODY:
                return HttpParameterType.BODY;
            case COOKIE:
                return HttpParameterType.COOKIE;
            case JSON:
                return HttpParameterType.JSON;
            case XML:
                return HttpParameterType.XML;
            case MULTIPART:
                return HttpParameterType.MULTIPART_ATTRIBUTE;
            default:
                return null; // HEADER and PATH are mutated by SQLiHunter directly.
        }
    }

    public static ParameterLocation fromMontoya(HttpParameterType type) {
        switch (type) {
            case URL:
                return URL;
            case BODY:
                return BODY;
            case COOKIE:
                return COOKIE;
            case JSON:
                return JSON;
            case XML:
            case XML_ATTRIBUTE:
                return XML;
            case MULTIPART_ATTRIBUTE:
                return MULTIPART;
            default:
                return BODY;
        }
    }
}
