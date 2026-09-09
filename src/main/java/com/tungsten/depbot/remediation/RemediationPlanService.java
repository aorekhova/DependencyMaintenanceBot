package com.tungsten.depbot.remediation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.report.actionable.ActionableReport;
import com.tungsten.depbot.report.actionable.ReportDestination;
import com.tungsten.depbot.report.actionable.ReportWriter;
import com.tungsten.depbot.report.actionable.WrittenReports;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Objects;

/**
 * Produces the remediation plan pair from the actionable report {@code scan} already published.
 *
 * <p>Never reads credentials and never contacts Mend: its only input is the already-redacted JSON
 * {@code scan} wrote, so there is no credential-bearing data path through this command at all.
 */
public final class RemediationPlanService {

    private final RemediationPlanBuilder builder;
    private final Path sourcePath;
    private final ReportDestination planDestination;
    private final ReportWriter writer;
    private final RemediationPlanJsonRenderer jsonRenderer = new RemediationPlanJsonRenderer();
    private final RemediationPlanMarkdownRenderer markdownRenderer = new RemediationPlanMarkdownRenderer();
    private final JsonMapper mapper = JsonMapper.builder().build();

    public RemediationPlanService(Clock clock, ReportDestination sourceDestination, ReportDestination planDestination) {
        this(clock, sourceDestination, planDestination, new ReportWriter());
    }

    RemediationPlanService(
            Clock clock, ReportDestination sourceDestination, ReportDestination planDestination, ReportWriter writer) {
        this.builder = new RemediationPlanBuilder(Objects.requireNonNull(clock, "clock"));
        this.sourcePath = Objects.requireNonNull(sourceDestination, "sourceDestination").jsonPath();
        this.planDestination = Objects.requireNonNull(planDestination, "planDestination");
        this.writer = Objects.requireNonNull(writer, "writer");
    }

    /** Removes any previous plan pair before a new one is generated, mirroring {@code scan}'s rule
     * that a partially-failed run must never leave a stale pair looking current. */
    public void invalidatePreviousPlan() {
        writer.invalidate(planDestination);
    }

    /**
     * @throws RemediationSourceException if the source report is missing or cannot be parsed
     * @throws com.tungsten.depbot.report.actionable.ReportWriteException if the plan cannot be written
     */
    public RemediationPlanOutcome generate() {
        ActionableReport sourceReport = readSourceReport();
        RemediationPlan plan = builder.build(sourceReport);

        String json = jsonRenderer.render(plan);
        String markdown = markdownRenderer.render(plan);

        WrittenReports written = writer.publish(planDestination, json, markdown);
        return new RemediationPlanOutcome(plan, written);
    }

    private ActionableReport readSourceReport() {
        if (!Files.exists(sourcePath)) {
            throw new RemediationSourceException(
                    "Could not find " + sourcePath + ". Run \"scan\" first to produce it.");
        }
        String content;
        try {
            content = Files.readString(sourcePath, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RemediationSourceException("Could not read " + sourcePath, e);
        }
        try {
            return mapper.readValue(content, ActionableReport.class);
        } catch (JsonProcessingException e) {
            throw new RemediationSourceException(
                    "Could not parse " + sourcePath + " as an actionable report", e);
        }
    }
}
