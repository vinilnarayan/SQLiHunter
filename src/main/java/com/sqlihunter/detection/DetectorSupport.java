package com.sqlihunter.detection;

/** Small shared helpers for detectors. */
final class DetectorSupport {

    private DetectorSupport() {
    }

    static String cap(String body, int maxBytes) {
        if (body == null) {
            return "";
        }
        return body.length() > maxBytes ? body.substring(0, maxBytes) : body;
    }
}
