package com.sqlihunter.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.sqlihunter.core.ScanConfig;
import com.sqlihunter.core.ScanEngine;
import com.sqlihunter.findings.FindingsStore;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;

/** Root SQLiHunter suite tab: Configuration, Progress, and Findings sub-tabs. */
public final class SQLiHunterTab extends JPanel {

    private final JTabbedPane tabs = new JTabbedPane();
    private final ConfigPanel configPanel;
    private final ProgressPanel progressPanel = new ProgressPanel();
    private final FindingsPanel findingsPanel;

    private static final int PROGRESS_INDEX = 1;

    public SQLiHunterTab(MontoyaApi api, ScanConfig config, FindingsStore store, ScanEngine engine) {
        setLayout(new BorderLayout());
        this.findingsPanel = new FindingsPanel(api, store, config);
        this.configPanel = new ConfigPanel(api, config, engine,
                progressPanel::attach,
                () -> tabs.setSelectedIndex(PROGRESS_INDEX));

        tabs.addTab("Configuration", new JScrollPane(configPanel));
        tabs.addTab("Progress", progressPanel);
        tabs.addTab("Findings", findingsPanel);
        add(tabs, BorderLayout.CENTER);
    }

    /** Called from the context menu to set the active scan target. */
    public void setSelectedRequest(HttpRequestResponse rr) {
        SwingUtilities.invokeLater(() -> {
            configPanel.setSelectedRequest(rr);
            tabs.setSelectedIndex(0);
        });
    }
}
