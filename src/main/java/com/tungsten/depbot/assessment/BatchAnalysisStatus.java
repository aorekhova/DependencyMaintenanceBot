package com.tungsten.depbot.assessment;

/**
 * What one whole-batch Vulnerability Analysis attempt actually delivered, as a single explicit
 * classification a reader should trust over reconstructing one from {@code analysis == null} plus a
 * free-text reason.
 */
public enum BatchAnalysisStatus {

    /** A validated, routable {@link BatchAnalysis} was produced -- normal per-finding/per-group routing. */
    COMPLETE,

    /**
     * The second attempt produced a document, but {@link AnalysisCoverageValidator} determined it does
     * not actually cover the batch it claims to -- answering findings {@code INCONCLUSIVE} with no
     * supporting evidence of examination, rather than genuinely reconstructing what either attempt had
     * established. Never routed as if it were a real verdict: the whole run stops before touching any
     * finding, and the analysis must be retried.
     */
    INCOMPLETE,

    /**
     * Both the first and the second Vulnerability Analysis attempt ran out of turns or time -- no
     * coverage-complete {@link BatchAnalysis} exists, but real partial progress from one or both attempts
     * does (see {@link PartialAnalysisState}). Distinct from {@code INCOMPLETE}: this is not discarded or
     * stopped on -- it is handed to a constrained Remediation Engineer fallback, per finding, so an
     * already-established upgrade direction still gets a chance to be implemented; a finding whose
     * direction cannot be reliably determined goes to Human Review instead of being guessed at.
     */
    PARTIAL,

    /** No usable document at all -- Claude failed outright, or every attempt to produce one failed to
     * parse or validate for a reason other than running out of turns or time. */
    FAILED
}
