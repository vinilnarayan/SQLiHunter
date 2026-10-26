package com.sqlihunter.ui;

import com.sqlihunter.core.ScanContext;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;
import java.awt.GridLayout;

/** Live scan progress display, driven by {@link ScanContext.ProgressListener}. */
public final class ProgressPanel extends JPanel implements ScanContext.ProgressListener {

    private final JLabel status = new JLabel("Idle");
    private final JLabel target = new JLabel("-");
    private final JLabel paramsTested = new JLabel("0 / 0");
    private final JLabel requestsSent = new JLabel("0");
    private final JLabel requestsRemaining = new JLabel("0");
    private final JLabel findings = new JLabel("0");
    private final JLabel errors = new JLabel("0");
    private final JLabel skipped = new JLabel("0");
    private final JLabel duration = new JLabel("0.0 s");
    private final JProgressBar budgetBar = new JProgressBar(0, 100);

    public ProgressPanel() {
        setLayout(new GridLayout(0, 2, 8, 6));
        setBorder(BorderFactory.createTitledBorder("Scan progress"));
        add(new JLabel("Status:")); add(status);
        add(new JLabel("Current target:")); add(target);
        add(new JLabel("Parameters tested:")); add(paramsTested);
        add(new JLabel("Requests sent:")); add(requestsSent);
        add(new JLabel("Requests remaining (budget):")); add(requestsRemaining);
        add(new JLabel("Findings:")); add(findings);
        add(new JLabel("Errors:")); add(errors);
        add(new JLabel("Skipped parameters:")); add(skipped);
        add(new JLabel("Duration:")); add(duration);
        budgetBar.setStringPainted(true);
        add(new JLabel("Budget used:")); add(budgetBar);
    }

    public void attach(ScanContext ctx) {
        ctx.setListener(this);
        onProgress(ctx);
    }

    @Override
    public void onProgress(ScanContext ctx) {
        SwingUtilities.invokeLater(() -> render(ctx, ctx.isPaused() ? "PAUSED" : "Running"));
    }

    @Override
    public void onFinished(ScanContext ctx) {
        SwingUtilities.invokeLater(() -> render(ctx, ctx.isCancelled() ? "Cancelled / finished" : "Finished"));
    }

    private void render(ScanContext ctx, String state) {
        status.setText(state);
        target.setText(ctx.currentTarget());
        paramsTested.setText(ctx.parametersTested() + " / " + ctx.parametersTotal());
        requestsSent.setText(Integer.toString(ctx.requestsSent()));
        requestsRemaining.setText(Integer.toString(ctx.requestsRemaining()));
        findings.setText(Integer.toString(ctx.findings()));
        errors.setText(Integer.toString(ctx.errors()));
        skipped.setText(Integer.toString(ctx.skipped()));
        duration.setText(String.format("%.1f s", ctx.elapsedMillis() / 1000.0));
        int pct = ctx.maxRequests() == 0 ? 0
                : (int) (100.0 * ctx.requestsSent() / ctx.maxRequests());
        budgetBar.setValue(Math.min(100, pct));
    }
}
