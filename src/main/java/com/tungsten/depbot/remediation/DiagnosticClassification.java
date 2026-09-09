package com.tungsten.depbot.remediation;

/**
 * Reserved for a future optional diagnostic fallback that would distinguish a group that is simply bad
 * on its own from one that only fails in combination with an already-accepted group (see
 * {@code VulnerabilityRemediationService}'s own javadoc for why this is deliberately not implemented
 * yet). Always {@link #DIAGNOSTIC_NOT_APPLICABLE} today.
 */
public enum DiagnosticClassification {
    GROUP_FAILURE,
    INTERACTION_FAILURE,
    DIAGNOSTIC_NOT_APPLICABLE
}
