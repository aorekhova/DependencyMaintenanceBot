package com.tungsten.depbot.git;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * A lightweight, git-only gate on what a unit is allowed to change, run before the orchestrator
 * ever stages or commits anything.
 *
 * <p>This is deliberately a heuristic, not a full secret scanner or an analysis of which test
 * assertions changed: it looks at file paths (from {@code git status}) and at added lines (from a
 * diff) for a short list of well-known danger signs. Real build/test validation
 * (<code>dependency:tree</code>, <code>compile</code>, running tests) is a separate, later step
 * that does not exist yet -- see the plan's "known, accepted risk" note. Passing this check means
 * "nothing obviously wrong was found," not "this change is correct."
 *
 * <p>Called twice per change by {@code RemediationChangeCommitter}: once before the orchestrator
 * stages anything ({@link #checkBeforeStaging}, which also catches Claude having staged something
 * itself -- forbidden, since only the orchestrator is allowed to run {@code git add}), and once
 * more against the fully staged diff right before the commit
 * ({@link #checkStagedDiff}).
 */
public final class RemediationDiffPolicy {

    private static final List<String> SKIP_TEST_MARKERS = List.of("skiptests", "maven.test.skip");

    public PolicyVerdict checkBeforeStaging(Path repoPath, GitCommandRunner git) {
        List<String> violations = new ArrayList<>();

        String stagedBeforeWeTouchedAnything = git.diffCached(repoPath);
        if (!stagedBeforeWeTouchedAnything.isBlank()) {
            violations.add("changes were already staged before the orchestrator staged anything -- "
                    + "Claude must never run git add");
        }

        violations.addAll(checkChangedFiles(git.status(repoPath)));
        violations.addAll(checkSkipTestMarkers(git.diff(repoPath)));

        return violations.isEmpty() ? PolicyVerdict.passed() : PolicyVerdict.rejected(violations);
    }

    public PolicyVerdict checkStagedDiff(Path repoPath, GitCommandRunner git) {
        List<String> violations = new ArrayList<>();

        violations.addAll(checkChangedFiles(git.status(repoPath)));
        violations.addAll(checkSkipTestMarkers(git.diffCached(repoPath)));

        return violations.isEmpty() ? PolicyVerdict.passed() : PolicyVerdict.rejected(violations);
    }

    private static List<String> checkChangedFiles(String statusPorcelain) {
        List<String> violations = new ArrayList<>();
        for (ChangedFile file : parseStatus(statusPorcelain)) {
            if (isSecretLike(file.path())) {
                violations.add("file looks like a secret or credential: " + file.path());
            }
            if (isTestFile(file.path()) && (file.deleted() || file.renamed())) {
                violations.add("a test file was deleted or renamed: " + file.path());
            }
            if (isInfraFile(file.path())) {
                violations.add("an unrelated CI/IDE file was touched: " + file.path());
            }
        }
        return violations;
    }

    private static List<String> checkSkipTestMarkers(String diffContent) {
        for (String line : diffContent.split("\\R")) {
            if (!line.startsWith("+") || line.startsWith("+++")) {
                continue;
            }
            String lower = line.toLowerCase(Locale.ROOT);
            for (String marker : SKIP_TEST_MARKERS) {
                if (lower.contains(marker)) {
                    return List.of("added content introduces a test-skipping marker (" + marker
                            + "): " + line.strip());
                }
            }
        }
        return List.of();
    }

    private static List<ChangedFile> parseStatus(String porcelain) {
        List<ChangedFile> files = new ArrayList<>();
        for (String line : porcelain.split("\\R")) {
            if (line.isBlank() || line.length() < 4) {
                continue;
            }
            String code = line.substring(0, 2);
            String rest = line.substring(3);
            boolean deleted = code.indexOf('D') >= 0;
            boolean renamed = code.indexOf('R') >= 0;

            String path = rest;
            int arrow = rest.indexOf(" -> ");
            if (arrow >= 0) {
                path = rest.substring(arrow + 4);
            }
            files.add(new ChangedFile(unquote(path), deleted, renamed));
        }
        return files;
    }

    private static String unquote(String path) {
        if (path.length() >= 2 && path.startsWith("\"") && path.endsWith("\"")) {
            return path.substring(1, path.length() - 1);
        }
        return path;
    }

    private static boolean isSecretLike(String path) {
        String name = fileName(path).toLowerCase(Locale.ROOT);
        return name.equals(".env")
                || name.startsWith(".env.")
                || name.endsWith(".pem")
                || name.endsWith(".key")
                || name.endsWith(".p12")
                || name.endsWith(".pfx")
                || name.endsWith(".jks")
                || name.contains("id_rsa")
                || name.contains("credentials");
    }

    private static boolean isTestFile(String path) {
        String normalized = path.replace('\\', '/');
        String name = fileName(normalized);
        return normalized.contains("src/test/") || name.matches(".*(Test|Tests|IT)\\.java$");
    }

    private static boolean isInfraFile(String path) {
        String normalized = path.replace('\\', '/');
        return normalized.startsWith(".github/")
                || normalized.startsWith(".gitlab-ci")
                || normalized.startsWith(".circleci/")
                || normalized.startsWith(".idea/")
                || normalized.startsWith(".vscode/")
                || normalized.equals("Jenkinsfile")
                || normalized.startsWith(".git/");
    }

    private static String fileName(String path) {
        String normalized = path.replace('\\', '/');
        int slash = normalized.lastIndexOf('/');
        return slash >= 0 ? normalized.substring(slash + 1) : normalized;
    }

    private record ChangedFile(String path, boolean deleted, boolean renamed) {
    }
}
