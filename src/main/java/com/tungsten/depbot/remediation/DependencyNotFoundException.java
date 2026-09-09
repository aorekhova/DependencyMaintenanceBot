package com.tungsten.depbot.remediation;

/**
 * The {@code --dependency} coordinates given to a pilot {@code remediate} run do not match any
 * library that can become a remediation unit -- either the remediation plan does not contain them
 * at all, or it contains them only under {@link RemediationPlan#manualAnalysisRequired()}, which
 * never produces a branch or a unit regardless of {@code --dependency}.
 */
public class DependencyNotFoundException extends RuntimeException {

    public DependencyNotFoundException(String safeMessage) {
        super(safeMessage);
    }
}
