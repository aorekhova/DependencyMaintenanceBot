package com.tungsten.depbot.git;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationDiffPolicyTest {

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();
    private final RemediationDiffPolicy policy = new RemediationDiffPolicy();

    @Test
    @DisplayName("an ordinary content change to an existing file is allowed")
    void ordinaryChangeIsAllowed() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve("file.txt"), "upgraded dependency version\n", StandardCharsets.UTF_8);

        PolicyVerdict verdict = policy.checkBeforeStaging(work, git);

        assertTrue(verdict.allowed(), verdict.violations().toString());
    }

    @Test
    @DisplayName("a secret-like file (.env) is rejected")
    void secretLikeFileIsRejected() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve(".env"), "TOKEN=abc\n", StandardCharsets.UTF_8);

        PolicyVerdict verdict = policy.checkBeforeStaging(work, git);

        assertFalse(verdict.allowed());
        assertTrue(verdict.violations().stream().anyMatch(v -> v.contains(".env")), verdict.violations().toString());
    }

    @Test
    @DisplayName("a private key file is rejected")
    void privateKeyFileIsRejected() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve("id_rsa"), "not a real key\n", StandardCharsets.UTF_8);

        PolicyVerdict verdict = policy.checkBeforeStaging(work, git);

        assertFalse(verdict.allowed());
    }

    @Test
    @DisplayName("deleting a test file is rejected")
    void deletingTestFileIsRejected() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Path testFile = work.resolve("src/test/java/example/ExampleTest.java");
        Files.createDirectories(testFile.getParent());
        Files.writeString(testFile, "class ExampleTest {}\n", StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "src/test/java/example/ExampleTest.java");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "add test");

        Files.delete(testFile);

        PolicyVerdict verdict = policy.checkBeforeStaging(work, git);

        assertFalse(verdict.allowed());
        assertTrue(verdict.violations().stream().anyMatch(v -> v.contains("ExampleTest.java")),
                verdict.violations().toString());
    }

    @Test
    @DisplayName("renaming a test file is rejected")
    void renamingTestFileIsRejected() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Path testFile = work.resolve("src/test/java/example/ExampleTest.java");
        Files.createDirectories(testFile.getParent());
        Files.writeString(testFile, "class ExampleTest { void a() {} void b() {} void c() {} }\n",
                StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "src/test/java/example/ExampleTest.java");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "add test");

        GitTestRepos.run(work, "git", "mv",
                "src/test/java/example/ExampleTest.java", "src/test/java/example/RenamedTest.java");

        PolicyVerdict verdict = policy.checkBeforeStaging(work, git);

        assertFalse(verdict.allowed());
    }

    @Test
    @DisplayName("modifying a test file's content (not deleting or renaming it) is not rejected by this rule")
    void modifyingTestFileContentIsNotRejectedByRenameOrDeleteRule() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Path testFile = work.resolve("src/test/java/example/ExampleTest.java");
        Files.createDirectories(testFile.getParent());
        Files.writeString(testFile, "class ExampleTest {}\n", StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "src/test/java/example/ExampleTest.java");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "add test");

        Files.writeString(testFile, "class ExampleTest { void newAssertion() {} }\n", StandardCharsets.UTF_8);

        PolicyVerdict verdict = policy.checkBeforeStaging(work, git);

        assertTrue(verdict.allowed(), verdict.violations().toString());
    }

    @Test
    @DisplayName("adding a CI workflow file is rejected as unrelated infrastructure")
    void ciFileIsRejected() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Path workflow = work.resolve(".github/workflows/build.yml");
        Files.createDirectories(workflow.getParent());
        Files.writeString(workflow, "name: build\n", StandardCharsets.UTF_8);

        PolicyVerdict verdict = policy.checkBeforeStaging(work, git);

        assertFalse(verdict.allowed());
    }

    @Test
    @DisplayName("introducing skipTests in an added line is rejected")
    void skipTestsMarkerIsRejected() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve("file.txt"), "hello\n<skipTests>true</skipTests>\n", StandardCharsets.UTF_8);

        PolicyVerdict verdict = policy.checkBeforeStaging(work, git);

        assertFalse(verdict.allowed());
        assertTrue(verdict.violations().stream().anyMatch(v -> v.contains("skiptests")),
                verdict.violations().toString());
    }

    @Test
    @DisplayName("maven.test.skip in an added line is rejected")
    void mavenTestSkipMarkerIsRejected() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve("file.txt"), "hello\n<maven.test.skip>true</maven.test.skip>\n",
                StandardCharsets.UTF_8);

        PolicyVerdict verdict = policy.checkBeforeStaging(work, git);

        assertFalse(verdict.allowed());
    }

    @Test
    @DisplayName("changes already staged before the orchestrator stages anything are rejected")
    void preExistingStagedChangesAreRejected() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve("file.txt"), "changed by claude directly\n", StandardCharsets.UTF_8);
        git.add(work);

        PolicyVerdict verdict = policy.checkBeforeStaging(work, git);

        assertFalse(verdict.allowed());
        assertTrue(verdict.violations().stream().anyMatch(v -> v.toLowerCase(java.util.Locale.ROOT).contains("staged")),
                verdict.violations().toString());
    }

    @Test
    @DisplayName("checkStagedDiff re-detects a skipTests marker in the fully staged diff")
    void checkStagedDiffDetectsSkipTestsAfterStaging() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve("file.txt"), "hello\n-DskipTests\n", StandardCharsets.UTF_8);
        git.add(work);

        PolicyVerdict verdict = policy.checkStagedDiff(work, git);

        assertFalse(verdict.allowed());
    }

    @Test
    @DisplayName("checkStagedDiff allows a clean, ordinary staged change")
    void checkStagedDiffAllowsOrdinaryStagedChange() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve("file.txt"), "upgraded dependency version\n", StandardCharsets.UTF_8);
        git.add(work);

        PolicyVerdict verdict = policy.checkStagedDiff(work, git);

        assertTrue(verdict.allowed(), verdict.violations().toString());
    }

    @Test
    @DisplayName("no changes at all is allowed by both checks")
    void noChangesIsAllowed() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);

        assertTrue(policy.checkBeforeStaging(work, git).allowed());
        assertTrue(policy.checkStagedDiff(work, git).allowed());
    }
}
