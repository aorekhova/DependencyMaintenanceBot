package com.tungsten.depbot.publication;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Renders the one Markdown summary posted as every automatically-created Merge Request's description --
 * one run may open several MRs (one per cohort), and every one of them gets the same, whole-run picture,
 * so a reviewer opening any of them sees the full context: what was automated, what still needs a human,
 * and why.
 *
 * <p><strong>Groups, libraries and commits are three different numbers, always kept apart.</strong> A
 * real pilot's summary once reported "Committed locally: 5" for what was actually four commits across
 * five libraries -- this renderer exists specifically so that mistake cannot recur: it counts remediation
 * groups, the distinct libraries inside them, and commits separately, and never collapses one into
 * another.
 */
public final class PublicationSummaryMarkdownRenderer {

    public String render(RunPublicationSummary summary) {
        Objects.requireNonNull(summary, "summary");

        StringBuilder md = new StringBuilder();
        md.append("# Dependency Maintenance Bot\n\n");
        md.append("**Run:** ").append(summary.runId()).append("\n\n");

        appendAutomaticRemediation(md, summary.commits());
        appendHumanReview(md, summary.humanReviewGroups());

        md.append("_No automatic merge will be performed._\n");
        return md.toString();
    }

    private static void appendAutomaticRemediation(StringBuilder md, List<RunPublicationSummary.CommitSummary> commits) {
        md.append("## Automatic remediation\n\n");
        if (commits.isEmpty()) {
            md.append("_No automatic remediation groups were published in this run._\n\n");
            return;
        }

        Set<String> libraries = new LinkedHashSet<>();
        commits.forEach(commit -> libraries.addAll(commit.memberCoordinates()));
        long dependencyValidationPassed = commits.stream().filter(RunPublicationSummary.CommitSummary::dependencyValidationPassed).count();
        long fullBuildPassed = commits.stream().filter(RunPublicationSummary.CommitSummary::fullBuildPassed).count();

        md.append("- ").append(check(true)).append(' ').append(commits.size())
                .append(commits.size() == 1 ? " remediation group\n" : " remediation groups\n");
        md.append("- ").append(check(true)).append(' ').append(libraries.size())
                .append(libraries.size() == 1 ? " library updated\n" : " libraries updated\n");
        md.append("- ").append(check(true)).append(' ').append(commits.size())
                .append(commits.size() == 1 ? " commit created\n" : " commits created\n");
        md.append("- ").append(check(dependencyValidationPassed == commits.size()))
                .append(" dependency validation passed for ").append(dependencyValidationPassed)
                .append('/').append(commits.size()).append(" commits\n");
        md.append("- ").append(check(fullBuildPassed == commits.size()))
                .append(fullBuildPassed == commits.size()
                        ? " full application build passed after every successful remediation commit\n"
                        : " full application build passed for " + fullBuildPassed + "/" + commits.size()
                                + " commits -- see each commit's own Remediation Report\n");
        md.append('\n');

        md.append("### Commits\n\n");
        for (RunPublicationSummary.CommitSummary commit : commits) {
            md.append("- `").append(shortSha(commit.commitSha())).append("` -- ")
                    .append(String.join(", ", commit.memberCoordinates())).append('\n');
        }
        md.append('\n');
    }

    private static void appendHumanReview(StringBuilder md, List<RunPublicationSummary.HumanReviewSummary> groups) {
        md.append("## Human review required\n\n");
        if (groups.isEmpty()) {
            md.append("_No group in this run needed human review._\n\n");
            return;
        }

        Set<String> libraries = new LinkedHashSet<>();
        groups.forEach(group -> libraries.addAll(group.memberCoordinates()));

        md.append("- ⚠ ").append(groups.size())
                .append(groups.size() == 1 ? " remediation group\n" : " remediation groups\n");
        md.append("- ⚠ ").append(libraries.size())
                .append(libraries.size() == 1 ? " library\n" : " libraries\n");
        md.append('\n');

        for (RunPublicationSummary.HumanReviewSummary group : groups) {
            String label = String.join(", ", group.memberCoordinates());
            if (group.issueUrl() != null) {
                md.append("- ").append(label).append(" -> ").append(group.issueUrl()).append('\n');
            } else {
                md.append("- ").append(label).append(" -> (issue not yet published)\n");
            }
        }
        md.append('\n');
    }

    private static String check(boolean allGood) {
        return allGood ? "✓" : "⚠";
    }

    private static String shortSha(String sha) {
        return sha.length() > 12 ? sha.substring(0, 12) : sha;
    }
}
