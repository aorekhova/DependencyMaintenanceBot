package com.tungsten.depbot.assessment;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.claude.JsonAnswerExtractor;

import java.util.Optional;

/**
 * Best-effort recovery of whatever structured {@link BatchAnalysis} shape survives in a Vulnerability
 * Analysis attempt's raw, incomplete answer text -- used only by the partial-analysis fallback (see
 * {@code VulnerabilityRemediationService}), never treated as a validated conclusion.
 *
 * <p>Unlike {@link BatchAnalysisParser}, this never enforces cross-document consistency --
 * {@link BatchAnalysisParser#parse} already failed for this text, which is exactly why the run reached
 * the partial-analysis fallback in the first place -- it only asks whether the JSON itself is well-formed
 * enough to bind at all. A truncated or malformed answer -- the common case for a genuine wall-clock kill,
 * which leaves no text at all -- yields {@link Optional#empty()}, which the fallback treats as "nothing
 * to salvage", never as an error.
 *
 * <p><strong>What this exists for, precisely:</strong> a real, partially-written
 * {@link AnalysisRemediationGroup} already carries the one thing Java must never override --
 * {@code automationSafety}. If Claude had already decided a finding is {@code HUMAN_REVIEW_REQUIRED} or
 * {@code AUTOMATION_BLOCKED} before running out of room, that decision is real engineering judgement and
 * must be honoured, never silently bypassed by routing the finding to the Remediation Engineer anyway.
 * The same recovered group also carries real membership, so genuinely related findings Claude had
 * already decided belong together are not accidentally split into independent, potentially contradictory
 * single-finding fallback attempts.
 */
public final class PartialAnalysisSalvage {

    private static final JsonMapper MAPPER = JsonMapper.builder()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    private PartialAnalysisSalvage() {
    }

    /** Best-effort recovery from one attempt's own raw text. Never throws. */
    public static Optional<BatchAnalysis> attemptSalvage(String rawText) {
        if (rawText == null || rawText.isBlank()) {
            return Optional.empty();
        }
        String json = JsonAnswerExtractor.lastJsonObject(rawText);
        if (json == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(MAPPER.readValue(json, BatchAnalysis.class));
        } catch (JsonProcessingException | RuntimeException e) {
            return Optional.empty();
        }
    }

    /**
     * Best-effort recovery across both attempts -- the second attempt's own text preferred (it is
     * whichever call was closest to producing a real answer), falling back to the first attempt's when
     * the second has nothing usable to offer.
     */
    public static Optional<BatchAnalysis> attemptSalvage(PartialAnalysisState state) {
        return attemptSalvage(state.attempt2().rawResultText())
                .or(() -> attemptSalvage(state.attempt1().rawResultText()));
    }
}
