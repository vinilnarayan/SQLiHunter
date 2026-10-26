package com.sqlihunter;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.sqlihunter.core.ScanConfig;
import com.sqlihunter.core.ScanEngine;
import com.sqlihunter.findings.FindingsStore;
import com.sqlihunter.ui.SQLiHunterContextMenu;
import com.sqlihunter.ui.SQLiHunterTab;

import javax.swing.SwingUtilities;

/**
 * SQLiHunter — a Burp Suite extension for detecting SQL injection in HTTP
 * services, built on the official Montoya API. Entry point registered via
 * {@code META-INF/MANIFEST.MF} (Gradle sets Main-Class is not used; Burp loads
 * the implementation of {@link BurpExtension} named in the build).
 *
 * <p>For authorised penetration testing and security assessment only.
 */
public final class SQLiHunterExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("SQLiHunter");
        api.logging().logToOutput("SQLiHunter loading... (authorised testing only)");

        ScanConfig config = new ScanConfig();
        FindingsStore store = new FindingsStore();
        ScanEngine engine = new ScanEngine(api, config, store);

        SQLiHunterTab tab = new SQLiHunterTab(api, config, store, engine);

        SwingUtilities.invokeLater(() ->
                api.userInterface().registerSuiteTab("SQLiHunter", tab));

        api.userInterface().registerContextMenuItemsProvider(
                new SQLiHunterContextMenu(api, config, store, tab));

        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("SQLiHunter unloading; stopping any active scan.");
            engine.stop();
        });

        api.logging().logToOutput("SQLiHunter loaded. Open the SQLiHunter tab to configure scans. "
                + "Active testing is OFF by default and requires an in-scope host allow-list.");
    }
}
