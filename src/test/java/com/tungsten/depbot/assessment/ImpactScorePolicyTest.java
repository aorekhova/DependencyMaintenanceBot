package com.tungsten.depbot.assessment;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ImpactScorePolicyTest {

    @Test
    @DisplayName("automationSafety AUTOMATIC_ALLOWED runs automatically, whatever the impact score is")
    void automaticAllowedRunsAutomaticallyRegardlessOfScore() {
        AnalysisRemediationGroup lowScore = Assessments.withAutomationSafety(
                Assessments.remediationGroup(3), AutomationSafety.AUTOMATIC_ALLOWED, "small and safe");
        AnalysisRemediationGroup highScore = Assessments.withAutomationSafety(
                Assessments.remediationGroup(9), AutomationSafety.AUTOMATIC_ALLOWED,
                "large, but a clean and well-validated path was found");

        for (AnalysisRemediationGroup group : List.of(lowScore, highScore)) {
            RemediationDecision decision = ImpactScorePolicy.decide(group);
            assertEquals(RemediationVerdict.AUTOMATIC_ALLOWED, decision.verdict(), group.impactScore().value() + "");
            assertTrue(decision.implementationAllowed());
        }
    }

    @Test
    @DisplayName("automationSafety HUMAN_REVIEW_REQUIRED no longer runs the implementation at all, "
            + "even at a low impact score -- it routes to Human Review Engineer instead")
    void humanReviewRequiredNeverRunsImplementation() {
        AnalysisRemediationGroup group = Assessments.withAutomationSafety(
                Assessments.remediationGroup(3), AutomationSafety.HUMAN_REVIEW_REQUIRED,
                "a coordinated dependency family with a proven binary-compatibility change");

        RemediationDecision decision = ImpactScorePolicy.decide(group);

        assertEquals(RemediationVerdict.HUMAN_REVIEW_REQUIRED, decision.verdict());
        assertFalse(decision.implementationAllowed(),
                "no implementation call ever runs for this verdict under the three-role model");
        assertTrue(decision.reason().contains("HUMAN_REVIEW_REQUIRED"), decision.reason());
    }

    @Test
    @DisplayName("automationSafety AUTOMATION_BLOCKED prevents any implementation call, "
            + "even at a low impact score")
    void automationBlockedPreventsImplementationRegardlessOfScore() {
        AnalysisRemediationGroup group = Assessments.withAutomationSafety(
                Assessments.remediationGroup(1), AutomationSafety.AUTOMATION_BLOCKED,
                "no safe remediation plan could be established");

        RemediationDecision decision = ImpactScorePolicy.decide(group);

        assertEquals(RemediationVerdict.MANUAL_REMEDIATION_REQUIRED, decision.verdict());
        assertFalse(decision.implementationAllowed());
        assertTrue(decision.reason().contains("AUTOMATION_BLOCKED"), decision.reason());
    }

    @Test
    @DisplayName("nothing to remediate is its own verdict, not a failure and not a manual hand-off")
    void noActionRequiredIsItsOwnVerdict() {
        RemediationDecision decision = ImpactScorePolicy.noActionRequired();

        assertEquals(RemediationVerdict.NO_ACTION_REQUIRED, decision.verdict());
        assertFalse(decision.implementationAllowed());
    }

    @Test
    @DisplayName("an inconclusive finding fails closed to a human")
    void inconclusiveFailsClosed() {
        RemediationDecision decision = ImpactScorePolicy.inconclusive();

        assertEquals(RemediationVerdict.MANUAL_REMEDIATION_REQUIRED, decision.verdict());
        assertFalse(decision.implementationAllowed());
    }

    @Test
    @DisplayName("a remediation group with no score fails closed rather than being assumed small")
    void missingScoreFailsClosed() {
        AnalysisRemediationGroup unscored =
                Assessments.withImpactScore(Assessments.remediationGroup(2), null);

        RemediationDecision decision = ImpactScorePolicy.decide(unscored);

        assertEquals(RemediationVerdict.MANUAL_REMEDIATION_REQUIRED, decision.verdict());
        assertTrue(decision.reason().contains("no impact score"), decision.reason());
    }

    @Test
    @DisplayName("a remediation group with no automation-safety decision fails closed")
    void missingAutomationSafetyFailsClosed() {
        AnalysisRemediationGroup noSafety = Assessments.withAutomationSafety(
                Assessments.remediationGroup(2), null, null);

        RemediationDecision decision = ImpactScorePolicy.decide(noSafety);

        assertEquals(RemediationVerdict.MANUAL_REMEDIATION_REQUIRED, decision.verdict());
        assertFalse(decision.implementationAllowed());
        assertTrue(decision.reason().contains("no automation-safety decision"), decision.reason());
    }

    @Test
    @DisplayName("a small score cannot authorise work when no ref was identified to branch from")
    void missingSourceRefFailsClosedEvenAtAScoreOfOne() {
        AnalysisRemediationGroup noRef = Assessments.withSourceRef(Assessments.remediationGroup(1), null);

        RemediationDecision decision = ImpactScorePolicy.decide(noRef);

        assertEquals(RemediationVerdict.MANUAL_REMEDIATION_REQUIRED, decision.verdict());
        assertFalse(decision.implementationAllowed());
        assertTrue(decision.reason().contains("source ref"), decision.reason());
    }

    @Test
    @DisplayName("a blank ref counts as no ref, not as one that happens to be empty")
    void blankSourceRefIsTreatedAsAbsent() {
        AnalysisRemediationGroup blankRef = Assessments.withSourceRef(Assessments.remediationGroup(1), "   ");

        assertEquals(RemediationVerdict.MANUAL_REMEDIATION_REQUIRED,
                ImpactScorePolicy.decide(blankRef).verdict());
    }

    @Test
    @DisplayName("a batch or finding that could not be read at all fails closed, with the reason kept")
    void unreadableAnalysisFailsClosed() {
        RemediationDecision decision = ImpactScorePolicy.failClosed("impactScore is missing");

        assertEquals(RemediationVerdict.MANUAL_REMEDIATION_REQUIRED, decision.verdict());
        assertFalse(decision.implementationAllowed());
        assertTrue(decision.reason().contains("impactScore is missing"), decision.reason());
    }

    @Test
    @DisplayName("exactly one verdict ever authorises an implementation, under the three-role model")
    void onlyOneVerdictAuthorisesImplementation() {
        for (RemediationVerdict verdict : RemediationVerdict.values()) {
            boolean allowed = new RemediationDecision(verdict, "any reason").implementationAllowed();
            assertEquals(verdict == RemediationVerdict.AUTOMATIC_ALLOWED, allowed, verdict.name());
        }
    }

    @Test
    @DisplayName("every decision carries a reason, so a skipped library is never unexplained")
    void everyDecisionCarriesAReason() {
        List<RemediationDecision> decisions = List.of(
                ImpactScorePolicy.decide(Assessments.remediationGroup(1)),
                ImpactScorePolicy.decide(Assessments.withAutomationSafety(
                        Assessments.remediationGroup(9), AutomationSafety.AUTOMATION_BLOCKED, "too risky")),
                ImpactScorePolicy.noActionRequired(),
                ImpactScorePolicy.inconclusive());

        for (RemediationDecision decision : decisions) {
            assertFalse(decision.reason().isBlank());
        }

        assertThrows(IllegalArgumentException.class, () -> new RemediationDecision(
                RemediationVerdict.AUTOMATIC_ALLOWED, "  "));
    }
}
