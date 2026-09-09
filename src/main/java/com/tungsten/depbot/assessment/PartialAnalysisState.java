package com.tungsten.depbot.assessment;

import java.util.Objects;

/**
 * What survives when <em>both</em> Vulnerability Analysis attempts ran out of turns or time -- never
 * discarded, and never turned into ten fabricated {@code INCONCLUSIVE} placeholders. This is handed
 * downstream (see {@code VulnerabilityRemediationService}'s partial-analysis fallback and
 * {@code ImplementationContext#partialAnalysisState()}) so the Remediation Engineer can be given a
 * genuine chance to carry out whatever upgrade direction was already reliably established -- from
 * Mend's own data and/or whatever either attempt actually wrote -- without ever being asked, or allowed,
 * to redo the vulnerability research itself.
 *
 * <p>Persisted once per run, as {@code partial-analysis-state.json}, specifically so an operator can see
 * how much progress the first attempt preserved, what the second attempt added, and why the pipeline
 * either continued with automatic remediation or sent a finding to Human Review.
 */
public record PartialAnalysisState(AnalysisAttemptSummary attempt1, AnalysisAttemptSummary attempt2) {

    public PartialAnalysisState {
        Objects.requireNonNull(attempt1, "attempt1");
        Objects.requireNonNull(attempt2, "attempt2");
    }
}
