package com.sqlihunter.findings;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe store of findings with deduplication by
 * (endpoint, parameter, detection type). Notifies listeners on the EDT caller's
 * behalf is NOT done here; the UI wraps notifications in SwingUtilities.
 */
public final class FindingsStore {

    public interface Listener {
        void onFindingAdded(Finding finding);
        void onCleared();
    }

    private final List<Finding> findings = new ArrayList<>();
    private final Set<String> seenKeys = new LinkedHashSet<>();
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();
    private final Object lock = new Object();

    public void addListener(Listener l) {
        listeners.add(l);
    }

    /**
     * Adds a finding unless an equivalent one (same dedup key) already exists.
     * @return true if stored, false if suppressed as a duplicate.
     */
    public boolean add(Finding finding) {
        synchronized (lock) {
            if (!seenKeys.add(finding.dedupKey())) {
                return false;
            }
            findings.add(finding);
        }
        for (Listener l : listeners) {
            l.onFindingAdded(finding);
        }
        return true;
    }

    public List<Finding> snapshot() {
        synchronized (lock) {
            return Collections.unmodifiableList(new ArrayList<>(findings));
        }
    }

    public int size() {
        synchronized (lock) {
            return findings.size();
        }
    }

    public void clear() {
        synchronized (lock) {
            findings.clear();
            seenKeys.clear();
        }
        for (Listener l : listeners) {
            l.onCleared();
        }
    }
}
