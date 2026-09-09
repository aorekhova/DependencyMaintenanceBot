package com.tungsten.depbot.remediation;

import com.tungsten.depbot.cli.ExitCode;
import com.tungsten.depbot.report.ConsoleReporter;
import com.tungsten.depbot.report.actionable.ReportWriteException;

import java.util.Objects;

/**
 * Runs the {@code plan-remediation} command and decides the resulting exit code.
 *
 * <p>Mirrors {@code ScanCommand}'s ordering: the previous plan pair is invalidated before the
 * source report is even read, so a run that fails partway through cannot leave a stale plan
 * looking current -- the same reasoning that applies to the actionable report itself.
 */
public final class RemediationPlanCommand {

    private final RemediationPlanService service;
    private final ConsoleReporter reporter;

    public RemediationPlanCommand(RemediationPlanService service, ConsoleReporter reporter) {
        this.service = Objects.requireNonNull(service, "service");
        this.reporter = Objects.requireNonNull(reporter, "reporter");
    }

    public ExitCode run() {
        try {
            service.invalidatePreviousPlan();
        } catch (ReportWriteException e) {
            return reportWriteFailure(e);
        }

        try {
            RemediationPlanOutcome outcome = service.generate();
            RemediationPlan plan = outcome.plan();
            reporter.printRemediationPlanSummary(
                    plan.critical().size(),
                    plan.high().size(),
                    plan.medium().size(),
                    plan.low().size(),
                    plan.manualAnalysisRequired().size());
            reporter.printRemediationPlanLocations(
                    outcome.written().jsonPath(), outcome.written().markdownPath());
            return ExitCode.SUCCESS;
        } catch (RemediationSourceException e) {
            reporter.printRemediationSourceError(e.getMessage());
            return ExitCode.REMEDIATION_SOURCE_ERROR;
        } catch (ReportWriteException e) {
            return reportWriteFailure(e);
        } catch (RuntimeException e) {
            reporter.printUnexpectedError();
            return ExitCode.UNEXPECTED_ERROR;
        }
    }

    private ExitCode reportWriteFailure(ReportWriteException e) {
        if (e.pairStateGuaranteed()) {
            reporter.printReportWriteError(e.getMessage());
        } else {
            reporter.printReportPairStateUnknown(e.getMessage(), e.unreconciledPaths());
        }
        return ExitCode.REPORT_WRITE_ERROR;
    }
}
