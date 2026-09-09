package com.tungsten.depbot.git;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationBranchNameTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("the name carries the run, the severity and the exact library")
    void nameCarriesRunSeverityAndLibrary() {
        assertEquals("remediation/20260810-120000-abc123/critical/org.bouncycastle__bcprov-jdk18on",
                RemediationBranchName.forLibrary("20260810-120000-abc123", "CRITICAL",
                        "org.bouncycastle", "bcprov-jdk18on"));
    }

    @Test
    @DisplayName("two libraries at the same severity get different branches, since their refs can differ")
    void twoLibrariesAtTheSameSeverityGetDifferentBranches() {
        String first = RemediationBranchName.forLibrary("run1", "HIGH", "g", "first");
        String second = RemediationBranchName.forLibrary("run1", "HIGH", "g", "second");

        assertFalse(first.equals(second),
                "a shared severity branch would have to be cut from one library's ref and would put the "
                        + "other's work on the wrong base");
    }

    @Test
    @DisplayName("dots in a groupId are kept, because readability matters and git allows them")
    void dotsInGroupIdAreKept() {
        assertTrue(RemediationBranchName.forLibrary("run1", "medium",
                "com.fasterxml.jackson.core", "jackson-databind")
                .endsWith("com.fasterxml.jackson.core__jackson-databind"));
    }

    @ParameterizedTest
    @CsvSource({
            "'a b',a_b",
            "'a~b',a_b",
            "'a^b',a_b",
            "'a:b',a_b",
            "'a?b',a_b",
            "'a*b',a_b",
            "'a[b',a_b",
            "'a..b',a_b",
            "'a....b',a_b",
            "'.leading',_leading",
            "'trailing.',trailing_",
            "'thing.lock',thing_lock",
            "'',_",
    })
    @DisplayName("everything git would refuse in a ref name is neutralised")
    void gitIllegalShapesAreNeutralised(String raw, String expected) {
        assertEquals(expected, RemediationBranchName.sanitize(raw));
    }

    @Test
    @DisplayName("git itself accepts a name built from hostile coordinates")
    void gitAcceptsANameBuiltFromHostileCoordinates() throws Exception {
        Path repo = GitTestRepos.createOriginAndSingleBranchClone(tempDir);
        String branch = RemediationBranchName.forLibrary(
                "run 1..2", "CRITICAL", "com.example..evil", "artifact:with*bad?chars.lock");

        // The real test: git accepts it. check-ref-format is what git uses on itself.
        GitTestRepos.run(repo, "git", "check-ref-format", "refs/heads/" + branch);
        new GitCommandRunner().createBranch(repo, branch, GitTestRepos.shaOf(repo, "master"));

        assertTrue(new GitCommandRunner().listRefs(repo).contains("refs/heads/" + branch));
    }
}
