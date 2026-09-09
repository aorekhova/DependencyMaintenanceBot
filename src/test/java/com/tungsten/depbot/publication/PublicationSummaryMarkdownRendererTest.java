package com.tungsten.depbot.publication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicationSummaryMarkdownRendererTest {

    private final PublicationSummaryMarkdownRenderer renderer = new PublicationSummaryMarkdownRenderer();

    /**
     * The exact shape that once produced the misleading "Committed locally: 5" for four commits: one
     * group of two libraries (one commit) plus three groups of one library each (three commits) -- four
     * commits, four groups, five libraries. None of those three numbers may be printed as another.
     */
    private static RunPublicationSummary fourCommitsFiveLibraries() {
        List<RunPublicationSummary.CommitSummary> commits = List.of(
                new RunPublicationSummary.CommitSummary("g-bcprov", "sha1",
                        List.of("org.bouncycastle:bcprov-jdk18on"), true, true),
                new RunPublicationSummary.CommitSummary("g-mchange", "sha2",
                        List.of("com.mchange:c3p0", "com.mchange:mchange-commons-java"), true, true),
                new RunPublicationSummary.CommitSummary("g-jackson", "sha3",
                        List.of("com.fasterxml.jackson.core:jackson-databind"), true, true),
                new RunPublicationSummary.CommitSummary("g-log4j", "sha4",
                        List.of("org.apache.logging.log4j:log4j-api"), true, true));
        return new RunPublicationSummary("run1", commits, List.of());
    }

    @Test
    @DisplayName("groups, libraries and commits are three different numbers, never collapsed into one another")
    void groupsLibrariesAndCommitsAreCountedSeparately() {
        String markdown = renderer.render(fourCommitsFiveLibraries());

        assertTrue(markdown.contains("4 remediation groups"), markdown);
        assertTrue(markdown.contains("5 libraries updated"), markdown);
        assertTrue(markdown.contains("4 commits created"), markdown);
        assertTrue(!markdown.contains("5 remediation groups"), markdown);
        assertTrue(!markdown.contains("4 libraries updated"), markdown);
    }

    @Test
    @DisplayName("a full build failure on one commit is surfaced, not folded into a blanket success claim")
    void aFullBuildFailureIsSurfacedNotHidden() {
        List<RunPublicationSummary.CommitSummary> commits = List.of(
                new RunPublicationSummary.CommitSummary("g-a", "sha1", List.of("g:a"), true, true),
                new RunPublicationSummary.CommitSummary("g-b", "sha2", List.of("g:b"), true, false));
        String markdown = renderer.render(new RunPublicationSummary("run1", commits, List.of()));

        assertTrue(!markdown.contains("full application build passed after every successful remediation commit"),
                markdown);
        assertTrue(markdown.contains("1/2"), markdown);
    }

    @Test
    @DisplayName("human review groups and their libraries are also counted separately, with links when published")
    void humanReviewGroupsAndLibrariesAreCountedSeparately() {
        List<RunPublicationSummary.HumanReviewSummary> groups = List.of(
                new RunPublicationSummary.HumanReviewSummary(
                        List.of("org.apache.httpcomponents.core5:httpcore5",
                                "org.apache.httpcomponents.client5:httpclient5"),
                        "https://gitlab.example.invalid/webapp/-/issues/1"),
                new RunPublicationSummary.HumanReviewSummary(
                        List.of("org.apache.struts:struts2-core"), null));

        String markdown = renderer.render(new RunPublicationSummary("run1", List.of(), groups));

        assertTrue(markdown.contains("2 remediation groups"), markdown);
        assertTrue(markdown.contains("3 libraries"), markdown);
        assertTrue(markdown.contains("https://gitlab.example.invalid/webapp/-/issues/1"), markdown);
        assertTrue(markdown.contains("issue not yet published"), markdown);
    }

    @Test
    @DisplayName("the summary always states plainly that no automatic merge will happen")
    void alwaysStatesNoAutomaticMerge() {
        String markdown = renderer.render(new RunPublicationSummary("run1", List.of(), List.of()));

        assertTrue(markdown.contains("No automatic merge will be performed"), markdown);
    }
}
