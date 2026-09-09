package com.tungsten.depbot.publication;

import java.util.List;
import java.util.Objects;

/**
 * Everything {@link PublicationSummaryMarkdownRenderer} needs to describe one run -- assembled by {@code
 * GitLabPublicationService} from what it actually did, never from counting library entries the way the
 * old, misleading "Committed locally: 5" summary line once did for four commits. A remediation
 * <em>group</em>, the <em>libraries</em> inside it, and the one <em>commit</em> it produced are three
 * different numbers, and this record keeps them three different fields on purpose.
 */
public record RunPublicationSummary(
        String runId, List<CommitSummary> commits, List<HumanReviewSummary> humanReviewGroups) {

    public RunPublicationSummary {
        Objects.requireNonNull(runId, "runId");
        commits = commits == null ? List.of() : List.copyOf(commits);
        humanReviewGroups = humanReviewGroups == null ? List.of() : List.copyOf(humanReviewGroups);
    }

    /** One remediation group's one successful, published commit. */
    public record CommitSummary(
            String groupId, String commitSha, List<String> memberCoordinates,
            boolean dependencyValidationPassed, boolean fullBuildPassed) {

        public CommitSummary {
            Objects.requireNonNull(groupId, "groupId");
            Objects.requireNonNull(commitSha, "commitSha");
            memberCoordinates = memberCoordinates == null ? List.of() : List.copyOf(memberCoordinates);
        }
    }

    /** One Human Review group -- no commit, by design; {@code issueUrl} is {@code null} until published. */
    public record HumanReviewSummary(List<String> memberCoordinates, String issueUrl) {

        public HumanReviewSummary {
            memberCoordinates = memberCoordinates == null ? List.of() : List.copyOf(memberCoordinates);
        }
    }
}
