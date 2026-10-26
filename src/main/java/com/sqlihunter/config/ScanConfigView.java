package com.sqlihunter.config;

/**
 * Read-only view of scan configuration exposed to detection modules, so the
 * detection package does not depend on the mutable core configuration object.
 */
public interface ScanConfigView {
    boolean passiveEnabled();
    boolean errorBasedEnabled();
    boolean booleanBlindEnabled();
    boolean timeBasedEnabled();
    boolean fingerprintingEnabled();

    int maxResponseBytes();

    int timeBasedDelaySeconds();
    int timeBasedMaxProbesPerParam();

    double booleanTrueSimilarityThreshold();
    double booleanFalseDivergenceThreshold();
    int booleanConfirmations();
}
