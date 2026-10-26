package com.sqlihunter.ui;

import burp.api.montoya.MontoyaApi;
import com.sqlihunter.core.ScanConfig;
import com.sqlihunter.findings.Finding;
import com.sqlihunter.findings.FindingsStore;
import com.sqlihunter.report.CsvReporter;
import com.sqlihunter.report.HtmlReporter;
import com.sqlihunter.report.JsonReporter;
import com.sqlihunter.report.Redactor;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Findings table with a detail view and export controls. */
public final class FindingsPanel extends JPanel implements FindingsStore.Listener {

    private final FindingsStore store;
    private final ScanConfig config;
    private final MontoyaApi api;
    private final List<Finding> rows = new ArrayList<>();
    private final FindingTableModel model = new FindingTableModel();
    private final JTable table = new JTable(model);

    private final JTextArea summaryArea = new JTextArea();
    private final JTextArea baselineReqArea = new JTextArea();
    private final JTextArea baselineRespArea = new JTextArea();
    private final JTextArea testReqArea = new JTextArea();
    private final JTextArea testRespArea = new JTextArea();

    /** Rebuilt on each selection: one "send to Repeater" button per request variant. */
    private final JPanel repeaterBar = new JPanel(new FlowLayout(FlowLayout.LEFT));

    public FindingsPanel(MontoyaApi api, FindingsStore store, ScanConfig config) {
        this.api = api;
        this.store = store;
        this.config = config;
        setLayout(new BorderLayout());

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelected();
            }
        });

        JTabbedPane detail = new JTabbedPane();
        detail.addTab("Summary", wrap(summaryArea));
        detail.addTab("Baseline request", wrap(baselineReqArea));
        detail.addTab("Baseline response", wrap(baselineRespArea));
        detail.addTab("Test request", wrap(testReqArea));
        detail.addTab("Test response", wrap(testRespArea));

        repeaterBar.setBorder(BorderFactory.createTitledBorder(
                "Manual verification — send to Repeater"));
        JPanel detailWrap = new JPanel(new BorderLayout());
        detailWrap.add(detail, BorderLayout.CENTER);
        detailWrap.add(repeaterBar, BorderLayout.SOUTH);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), detailWrap);
        split.setResizeWeight(0.45);
        add(split, BorderLayout.CENTER);
        add(buildToolbar(), BorderLayout.NORTH);

        store.addListener(this);
        refreshRepeaterBar(null);
    }

    /** Rebuild the Repeater buttons for the given finding (or show a hint when none). */
    private void refreshRepeaterBar(Finding f) {
        repeaterBar.removeAll();
        List<Finding.RepeaterEntry> entries = (f == null) ? List.of() : f.repeaterEntries();
        if (entries.isEmpty()) {
            repeaterBar.add(new javax.swing.JLabel(
                    "Select a finding to send its request(s) to Repeater."));
        } else {
            if (entries.size() > 1) {
                JButton all = new JButton("Send all to Repeater");
                all.addActionListener(e -> {
                    for (Finding.RepeaterEntry en : entries) {
                        sendToRepeater(f, en);
                    }
                });
                repeaterBar.add(all);
            }
            for (Finding.RepeaterEntry en : entries) {
                JButton b = new JButton("Send: " + en.label());
                b.addActionListener(e -> sendToRepeater(f, en));
                repeaterBar.add(b);
            }
        }
        repeaterBar.revalidate();
        repeaterBar.repaint();
    }

    private void sendToRepeater(Finding f, Finding.RepeaterEntry entry) {
        try {
            String tabName = "SQLiH " + f.paramName() + " " + entry.label();
            api.repeater().sendToRepeater(entry.request(), tabName);
            api.logging().logToOutput("[SQLiHunter] Sent to Repeater: " + tabName);
        } catch (RuntimeException ex) {
            api.logging().logToError("Failed to send request to Repeater", ex);
            JOptionPane.showMessageDialog(this, "Could not send to Repeater: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private JScrollPane wrap(JTextArea area) {
        area.setEditable(false);
        area.setLineWrap(false);
        area.setFont(new java.awt.Font("Monospaced", java.awt.Font.PLAIN, 12));
        return new JScrollPane(area);
    }

    private JPanel buildToolbar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bar.setBorder(BorderFactory.createTitledBorder("Findings & reporting"));
        JButton json = new JButton("Export JSON");
        JButton csv = new JButton("Export CSV");
        JButton html = new JButton("Export HTML");
        JButton clear = new JButton("Clear");
        json.addActionListener(e -> export("json"));
        csv.addActionListener(e -> export("csv"));
        html.addActionListener(e -> export("html"));
        clear.addActionListener(e -> {
            int c = JOptionPane.showConfirmDialog(this, "Clear all findings?", "Confirm",
                    JOptionPane.YES_NO_OPTION);
            if (c == JOptionPane.YES_OPTION) {
                store.clear();
            }
        });
        bar.add(json);
        bar.add(csv);
        bar.add(html);
        bar.add(clear);
        return bar;
    }

    private void export(String kind) {
        List<Finding> snapshot = store.snapshot();
        if (snapshot.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No findings to export.");
            return;
        }
        Redactor redactor = new Redactor(config.redactReports());
        String content;
        String ext;
        switch (kind) {
            case "json":
                content = new JsonReporter(redactor).report(snapshot);
                ext = "json";
                break;
            case "csv":
                content = new CsvReporter().report(snapshot);
                ext = "csv";
                break;
            default:
                content = new HtmlReporter(redactor).report(snapshot);
                ext = "html";
                break;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("sqlihunter-report." + ext));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path path = chooser.getSelectedFile().toPath();
        try {
            Files.write(path, content.getBytes(StandardCharsets.UTF_8));
            JOptionPane.showMessageDialog(this, "Saved " + snapshot.size() + " finding(s) to\n" + path
                    + (config.redactReports() ? "\n(secrets redacted)" : "\n(NOT redacted)"));
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Failed to save: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void showSelected() {
        int r = table.getSelectedRow();
        if (r < 0 || r >= rows.size()) {
            return;
        }
        Finding f = rows.get(r);
        summaryArea.setText(buildSummary(f));
        summaryArea.setCaretPosition(0);
        baselineReqArea.setText(f.baselineRequest());
        baselineRespArea.setText(f.baselineResponse());
        testReqArea.setText(f.testRequest());
        testRespArea.setText(f.testResponse());
        refreshRepeaterBar(f);
    }

    private String buildSummary(Finding f) {
        StringBuilder sb = new StringBuilder();
        sb.append(f.title()).append("\n\n");
        sb.append("Severity:   ").append(f.severity()).append('\n');
        sb.append("Confidence: ").append(f.confidence()).append('\n');
        sb.append("Type:       ").append(f.type()).append('\n');
        sb.append("Endpoint:   ").append(f.method()).append(' ').append(f.host()).append(f.endpoint()).append('\n');
        sb.append("Parameter:  ").append(f.paramName()).append(" (").append(f.paramLocation().display()).append(")\n");
        sb.append("Database:   ").append(f.dbFamily().display()).append('\n');
        sb.append("Detection:  ").append(f.detectionMethod()).append('\n');
        sb.append("OWASP:      ").append(Finding.OWASP_CATEGORY).append('\n');
        if (f.cvssVector() != null) {
            sb.append("CVSS v4.0:  ").append(f.cvssVector()).append('\n');
        }
        sb.append("\nPreconditions:\n").append(f.preconditions()).append('\n');
        sb.append("\nEvidence:\n").append(f.evidenceSummary()).append('\n');
        sb.append("\nConfidence & limitations:\n").append(f.limitations()).append('\n');
        sb.append("\nSteps to reproduce:\n");
        int i = 1;
        for (String s : f.reproSteps()) {
            sb.append("  ").append(i++).append(". ").append(s).append('\n');
        }
        sb.append("\nRemediation:\n").append(f.remediation()).append('\n');
        sb.append("\nReferences:\n");
        for (String ref : f.references()) {
            sb.append("  - ").append(ref).append('\n');
        }
        return sb.toString();
    }

    // ---- FindingsStore.Listener ----
    @Override
    public void onFindingAdded(Finding finding) {
        SwingUtilities.invokeLater(() -> {
            rows.add(finding);
            model.fireTableRowsInserted(rows.size() - 1, rows.size() - 1);
        });
    }

    @Override
    public void onCleared() {
        SwingUtilities.invokeLater(() -> {
            rows.clear();
            model.fireTableDataChanged();
            summaryArea.setText("");
            baselineReqArea.setText("");
            baselineRespArea.setText("");
            testReqArea.setText("");
            testRespArea.setText("");
            refreshRepeaterBar(null);
        });
    }

    private final class FindingTableModel extends AbstractTableModel {
        private final String[] cols = {"Severity", "Confidence", "Type", "Method",
                "Host", "Endpoint", "Parameter", "Location", "DB", "Status"};

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return cols.length; }
        @Override public String getColumnName(int c) { return cols[c]; }

        @Override
        public Object getValueAt(int r, int c) {
            Finding f = rows.get(r);
            switch (c) {
                case 0: return f.severity();
                case 1: return f.confidence();
                case 2: return f.type();
                case 3: return f.method();
                case 4: return f.host();
                case 5: return f.endpoint();
                case 6: return f.paramName();
                case 7: return f.paramLocation().display();
                case 8: return f.dbFamily().display();
                case 9: return f.httpStatus();
                default: return "";
            }
        }
    }
}
