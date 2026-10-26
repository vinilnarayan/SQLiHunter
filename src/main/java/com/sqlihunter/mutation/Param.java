package com.sqlihunter.mutation;

import java.util.Objects;

/**
 * An injectable input selected for testing. For JSON bodies {@code name} is a
 * JSON pointer (e.g. {@code /user/id} or {@code /items/0/sku}); for PATH it is
 * the zero-based segment index as a string; otherwise it is the parameter name.
 */
public final class Param {

    private final String name;
    private final String originalValue;
    private final ParameterLocation location;

    public Param(String name, String originalValue, ParameterLocation location) {
        this.name = Objects.requireNonNull(name, "name");
        this.originalValue = originalValue == null ? "" : originalValue;
        this.location = Objects.requireNonNull(location, "location");
    }

    public String name() {
        return name;
    }

    public String originalValue() {
        return originalValue;
    }

    public ParameterLocation location() {
        return location;
    }

    /** Stable key used for finding deduplication and UI display. */
    public String key() {
        return location.name() + ":" + name;
    }

    @Override
    public String toString() {
        return name + " (" + location.display() + ")";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Param)) return false;
        Param p = (Param) o;
        return name.equals(p.name) && location == p.location;
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, location);
    }
}
