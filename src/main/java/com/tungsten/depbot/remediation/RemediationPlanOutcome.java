package com.tungsten.depbot.remediation;

import com.tungsten.depbot.report.actionable.WrittenReports;

/** Bundles the plan that was built with where it was written, for a single return from the service. */
public record RemediationPlanOutcome(RemediationPlan plan, WrittenReports written) {
}
