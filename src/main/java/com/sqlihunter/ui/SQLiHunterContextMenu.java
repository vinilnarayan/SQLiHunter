package com.sqlihunter.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.sqlihunter.core.ScanConfig;
import com.sqlihunter.detection.PassiveDetector;
import com.sqlihunter.findings.Finding;
import com.sqlihunter.findings.FindingsStore;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

/**
 * Context-menu actions available on selected requests in Proxy history,
 * Repeater, Logger, etc.: set a scan target, or passively scan the selection.
 */
public final class SQLiHunterContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final ScanConfig config;
    private final FindingsStore store;
    private final SQLiHunterTab tab;

    public SQLiHunterContextMenu(MontoyaApi api, ScanConfig config, FindingsStore store, SQLiHunterTab tab) {
        this.api = api;
        this.config = config;
        this.store = store;
        this.tab = tab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = collect(event);
        if (selected.isEmpty()) {
            return List.of();
        }
        List<Component> items = new ArrayList<>();

        JMenuItem setTarget = new JMenuItem("SQLiHunter: set as scan target");
        setTarget.addActionListener(e -> tab.setSelectedRequest(selected.get(0)));
        items.add(setTarget);

        JMenuItem passive = new JMenuItem("SQLiHunter: passive-scan selected item(s)");
        passive.addActionListener(e -> runPassive(selected));
        items.add(passive);

        return items;
    }

    private void runPassive(List<HttpRequestResponse> selected) {
        // Passive analysis generates no traffic; safe to run on any selection.
        new Thread(() -> {
            PassiveDetector detector = new PassiveDetector();
            int added = 0;
            for (HttpRequestResponse rr : selected) {
                try {
                    for (Finding f : detector.analyze(rr, config)) {
                        if (store.add(f)) {
                            added++;
                        }
                    }
                } catch (RuntimeException ex) {
                    api.logging().logToError("Passive scan error", ex);
                }
            }
            api.logging().logToOutput("[SQLiHunter] Passive scan of " + selected.size()
                    + " item(s) complete; " + added + " new finding(s).");
        }, "sqlihunter-passive").start();
    }

    private List<HttpRequestResponse> collect(ContextMenuEvent event) {
        List<HttpRequestResponse> list = new ArrayList<>();
        if (event.messageEditorRequestResponse().isPresent()) {
            list.add(event.messageEditorRequestResponse().get().requestResponse());
        }
        list.addAll(event.selectedRequestResponses());
        return list;
    }
}
