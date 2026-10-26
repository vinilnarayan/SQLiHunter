package com.sqlihunter.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.sqlihunter.core.ScanConfig;
import com.sqlihunter.core.ScanContext;
import com.sqlihunter.core.ScanEngine;
import com.sqlihunter.core.ScanProfile;
import com.sqlihunter.mutation.Param;
import com.sqlihunter.mutation.RequestMutator;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.SpinnerNumberModel;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/** Scan configuration, parameter selection, and start/pause/resume/stop controls. */
public final class ConfigPanel extends JPanel {

    private final MontoyaApi api;
    private final ScanConfig config;
    private final ScanEngine engine;
    private final Consumer<ScanContext> onScanStarted;
    private final Runnable showProgress;

    private HttpRequestResponse selected;
    private final RequestMutator mutator = new RequestMutator();

    private final JLabel targetLabel = new JLabel("No request selected. Right-click a request → "
            + "\"SQLiHunter: set as scan target\".");
    private final DefaultListModel<Param> paramModel = new DefaultListModel<>();
    private final JList<Param> paramList = new JList<>(paramModel);

    private final JComboBox<ScanProfile> profileBox = new JComboBox<>(ScanProfile.values());

    private final JCheckBox cbPassive = new JCheckBox("Passive analysis");
    private final JCheckBox cbActive = new JCheckBox("Active testing");
    private final JCheckBox cbError = new JCheckBox("Error-based");
    private final JCheckBox cbBoolean = new JCheckBox("Boolean-blind");
    private final JCheckBox cbTime = new JCheckBox("Time-based (opt-in)");
    private final JCheckBox cbFingerprint = new JCheckBox("DB fingerprinting");

    private final JCheckBox cbUrl = new JCheckBox("URL");
    private final JCheckBox cbBody = new JCheckBox("Body");
    private final JCheckBox cbCookie = new JCheckBox("Cookies");
    private final JCheckBox cbJson = new JCheckBox("JSON");
    private final JCheckBox cbXml = new JCheckBox("XML");
    private final JCheckBox cbHeaders = new JCheckBox("Headers");
    private final JCheckBox cbPath = new JCheckBox("Path");

    private final JTextArea scopeHosts = new JTextArea(3, 24);
    private final JTextArea scopePaths = new JTextArea(2, 24);
    private final JTextArea excludedParams = new JTextArea(2, 24);
    private final JTextArea excludedPaths = new JTextArea(2, 24);

    private final JSpinner spMaxReq = spinner(300, 1, 100000, 10);
    private final JSpinner spConc = spinner(4, 1, 64, 1);
    private final JSpinner spRps = spinner(5.0, 0.1, 100.0, 0.5);
    private final JSpinner spTimeout = spinner(600, 1, 86400, 10);
    private final JSpinner spRespTimeout = spinner(15000, 1000, 120000, 1000);
    private final JSpinner spMaxBytes = spinner(2000000, 10000, 50000000, 100000);
    private final JSpinner spTimeDelay = spinner(5, 1, 30, 1);
    private final JSpinner spBoolConf = spinner(2, 1, 5, 1);
    private final JCheckBox cbRedact = new JCheckBox("Redact secrets in saved reports", true);

    private final JButton startBtn = new JButton("Start");
    private final JButton pauseBtn = new JButton("Pause");
    private final JButton resumeBtn = new JButton("Resume");
    private final JButton stopBtn = new JButton("Stop");

    public ConfigPanel(MontoyaApi api, ScanConfig config, ScanEngine engine,
                       Consumer<ScanContext> onScanStarted, Runnable showProgress) {
        this.api = api;
        this.config = config;
        this.engine = engine;
        this.onScanStarted = onScanStarted;
        this.showProgress = showProgress;

        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        add(buildTargetSection());
        add(buildProfileAndTechniques());
        add(buildLocations());
        add(buildScope());
        add(buildLimits());
        add(buildControls());

        initFromConfig();
        wireProfile();
    }

    // ---- sections ----

    private JPanel buildTargetSection() {
        JPanel p = titled("1. Target & parameters");
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.add(targetLabel);
        paramList.setVisibleRowCount(6);
        JScrollPane sp = new JScrollPane(paramList);
        sp.setPreferredSize(new Dimension(500, 120));
        p.add(sp);
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton refresh = new JButton("Re-discover parameters");
        refresh.addActionListener(e -> rediscover());
        row.add(refresh);
        row.add(new JLabel("(no selection = test all eligible)"));
        p.add(row);
        return p;
    }

    private JPanel buildProfileAndTechniques() {
        JPanel p = titled("2. Profile & techniques");
        p.setLayout(new GridLayout(0, 1));
        JPanel pr = new JPanel(new FlowLayout(FlowLayout.LEFT));
        pr.add(new JLabel("Profile:"));
        pr.add(profileBox);
        p.add(pr);
        JPanel tech = new JPanel(new FlowLayout(FlowLayout.LEFT));
        tech.add(cbPassive); tech.add(cbActive); tech.add(cbError);
        tech.add(cbBoolean); tech.add(cbTime); tech.add(cbFingerprint);
        p.add(tech);
        return p;
    }

    private JPanel buildLocations() {
        JPanel p = titled("3. Parameter locations to test");
        p.setLayout(new FlowLayout(FlowLayout.LEFT));
        p.add(cbUrl); p.add(cbBody); p.add(cbJson); p.add(cbCookie);
        p.add(cbXml); p.add(cbHeaders); p.add(cbPath);
        return p;
    }

    private JPanel buildScope() {
        JPanel p = titled("4. Scope & exclusions (one entry per line)");
        p.setLayout(new GridLayout(2, 2, 10, 6));
        p.add(labeled("In-scope hosts (allow-list; *.example.com ok)", scopeHosts));
        p.add(labeled("In-scope path prefixes (optional)", scopePaths));
        p.add(labeled("Excluded parameter names", excludedParams));
        p.add(labeled("Excluded path substrings (state-changing)", excludedPaths));
        return p;
    }

    private JPanel buildLimits() {
        JPanel p = titled("5. Budgets, rate & safety limits");
        p.setLayout(new GridLayout(0, 4, 8, 6));
        p.add(new JLabel("Max requests:")); p.add(spMaxReq);
        p.add(new JLabel("Max concurrency:")); p.add(spConc);
        p.add(new JLabel("Requests / second:")); p.add(spRps);
        p.add(new JLabel("Scan timeout (s):")); p.add(spTimeout);
        p.add(new JLabel("Response timeout (ms):")); p.add(spRespTimeout);
        p.add(new JLabel("Max response bytes:")); p.add(spMaxBytes);
        p.add(new JLabel("Time-based delay (s):")); p.add(spTimeDelay);
        p.add(new JLabel("Boolean confirmations:")); p.add(spBoolConf);
        p.add(cbRedact);
        return p;
    }

    private JPanel buildControls() {
        JPanel p = titled("6. Run");
        p.setLayout(new FlowLayout(FlowLayout.LEFT));
        startBtn.addActionListener(e -> start());
        pauseBtn.addActionListener(e -> engine.pause());
        resumeBtn.addActionListener(e -> engine.resume());
        stopBtn.addActionListener(e -> engine.stop());
        p.add(startBtn); p.add(pauseBtn); p.add(resumeBtn); p.add(stopBtn);
        return p;
    }

    // ---- behaviour ----

    public void setSelectedRequest(HttpRequestResponse rr) {
        this.selected = rr;
        try {
            targetLabel.setText(rr.request().method() + "  " + rr.request().url());
            String host = rr.request().httpService().host();
            if (!containsLine(scopeHosts, host)) {
                scopeHosts.append((scopeHosts.getText().isBlank() ? "" : "\n") + host);
            }
        } catch (RuntimeException ex) {
            targetLabel.setText("Selected request (URL unavailable)");
        }
        rediscover();
    }

    private void rediscover() {
        paramModel.clear();
        if (selected == null) {
            return;
        }
        RequestMutator.Discovery d = mutator.discover(selected.request(),
                cbHeaders.isSelected(), config.enabledHeaderNames(), cbPath.isSelected());
        for (Param p : d.params) {
            paramModel.addElement(p);
        }
        for (String w : d.warnings) {
            api.logging().logToOutput("[SQLiHunter] " + w);
        }
    }

    private void start() {
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Select a target request first (right-click → set as scan target).");
            return;
        }
        if (engine.isRunning()) {
            JOptionPane.showMessageDialog(this, "A scan is already running.");
            return;
        }
        applyToConfig();

        List<Param> chosen = new ArrayList<>(paramList.getSelectedValuesList());

        if (config.activeEnabled()) {
            if (config.inScopeHosts().isEmpty()) {
                JOptionPane.showMessageDialog(this,
                        "Active testing requires at least one in-scope host in the allow-list.",
                        "Scope required", JOptionPane.WARNING_MESSAGE);
                return;
            }
            String msg = "You are about to run ACTIVE SQL injection tests.\n\n"
                    + "Target: " + safeUrl() + "\n"
                    + "Parameters: " + (chosen.isEmpty() ? "all eligible" : chosen.size() + " selected") + "\n"
                    + "Max requests: " + config.maxRequests() + "   Rate: " + config.requestsPerSecond() + "/s\n"
                    + "Techniques: " + techniquesSummary() + "\n\n"
                    + "Only proceed against systems you are explicitly authorised to test.\nContinue?";
            int c = JOptionPane.showConfirmDialog(this, msg, "Confirm active testing",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (c != JOptionPane.OK_OPTION) {
                return;
            }
        }

        ScanContext ctx = engine.startScan(selected, chosen);
        if (ctx != null) {
            onScanStarted.accept(ctx);
            showProgress.run();
        } else if (config.activeEnabled()) {
            JOptionPane.showMessageDialog(this,
                    "Active scan did not start. Check the target is in scope and the allow-list,\n"
                    + "and see the Extensions output log for details.",
                    "Not started", JOptionPane.WARNING_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this, "Passive analysis complete (see Findings tab).");
        }
    }

    private void applyToConfig() {
        config.applyProfile((ScanProfile) profileBox.getSelectedItem());
        config.setPassiveEnabled(cbPassive.isSelected());
        config.setActiveEnabled(cbActive.isSelected());
        config.setErrorBasedEnabled(cbError.isSelected());
        config.setBooleanBlindEnabled(cbBoolean.isSelected());
        config.setTimeBasedEnabled(cbTime.isSelected());
        config.setFingerprintingEnabled(cbFingerprint.isSelected());

        config.setTestUrl(cbUrl.isSelected());
        config.setTestBody(cbBody.isSelected());
        config.setTestCookies(cbCookie.isSelected());
        config.setTestJson(cbJson.isSelected());
        config.setTestXml(cbXml.isSelected());
        config.setTestHeaders(cbHeaders.isSelected());
        config.setTestPath(cbPath.isSelected());

        replace(config.inScopeHosts(), lines(scopeHosts));
        replace(config.inScopePathPrefixes(), lines(scopePaths));
        replace(config.excludedParamNames(), lines(excludedParams));
        replace(config.excludedPathSubstrings(), lines(excludedPaths));

        config.setMaxRequests((Integer) spMaxReq.getValue());
        config.setMaxConcurrency((Integer) spConc.getValue());
        config.setRequestsPerSecond(((Number) spRps.getValue()).doubleValue());
        config.setScanTimeoutSeconds((Integer) spTimeout.getValue());
        config.setResponseTimeoutMillis(((Integer) spRespTimeout.getValue()).longValue());
        config.setMaxResponseBytes((Integer) spMaxBytes.getValue());
        config.setTimeBasedDelaySeconds((Integer) spTimeDelay.getValue());
        config.setBooleanConfirmations((Integer) spBoolConf.getValue());
        config.setRedactReports(cbRedact.isSelected());
    }

    private void initFromConfig() {
        profileBox.setSelectedItem(config.profile());
        cbPassive.setSelected(config.passiveEnabled());
        cbActive.setSelected(config.activeEnabled());
        cbError.setSelected(config.errorBasedEnabled());
        cbBoolean.setSelected(config.booleanBlindEnabled());
        cbTime.setSelected(config.timeBasedEnabled());
        cbFingerprint.setSelected(config.fingerprintingEnabled());
        cbUrl.setSelected(config.testUrl());
        cbBody.setSelected(config.testBody());
        cbCookie.setSelected(config.testCookies());
        cbJson.setSelected(config.testJson());
        cbXml.setSelected(config.testXml());
        cbHeaders.setSelected(config.testHeaders());
        cbPath.setSelected(config.testPath());
        excludedParams.setText(String.join("\n", config.excludedParamNames()));
        excludedPaths.setText(String.join("\n", config.excludedPathSubstrings()));
        cbRedact.setSelected(config.redactReports());
    }

    private void wireProfile() {
        profileBox.addActionListener(e -> {
            ScanProfile p = (ScanProfile) profileBox.getSelectedItem();
            if (p != ScanProfile.CUSTOM) {
                config.applyProfile(p);
                initFromConfig();
                profileBox.setSelectedItem(p);
            }
        });
    }

    // ---- helpers ----

    private String techniquesSummary() {
        List<String> t = new ArrayList<>();
        if (cbError.isSelected()) t.add("error-based");
        if (cbBoolean.isSelected()) t.add("boolean-blind");
        if (cbTime.isSelected()) t.add("time-based");
        return String.join(", ", t);
    }

    private String safeUrl() {
        try { return selected.request().url(); } catch (RuntimeException e) { return "(unknown)"; }
    }

    private static JPanel titled(String title) {
        JPanel p = new JPanel();
        p.setBorder(BorderFactory.createTitledBorder(title));
        p.setAlignmentX(LEFT_ALIGNMENT);
        return p;
    }

    private static JPanel labeled(String label, JTextArea area) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.add(new JLabel(label));
        p.add(new JScrollPane(area));
        return p;
    }

    private static JSpinner spinner(Number value, Number min, Number max, Number step) {
        SpinnerNumberModel m;
        if (value instanceof Double) {
            m = new SpinnerNumberModel(value.doubleValue(), min.doubleValue(), max.doubleValue(), step.doubleValue());
        } else {
            m = new SpinnerNumberModel(value.intValue(), min.intValue(), max.intValue(), step.intValue());
        }
        return new JSpinner(m);
    }

    private static List<String> lines(JTextArea area) {
        List<String> out = new ArrayList<>();
        for (String line : area.getText().split("\\R")) {
            String t = line.trim();
            if (!t.isEmpty()) {
                out.add(t);
            }
        }
        return out;
    }

    private static void replace(List<String> target, List<String> values) {
        target.clear();
        target.addAll(values);
    }

    private static boolean containsLine(JTextArea area, String value) {
        for (String line : area.getText().split("\\R")) {
            if (line.trim().equalsIgnoreCase(value)) {
                return true;
            }
        }
        return false;
    }

    private static final float LEFT_ALIGNMENT = java.awt.Component.LEFT_ALIGNMENT;
}
