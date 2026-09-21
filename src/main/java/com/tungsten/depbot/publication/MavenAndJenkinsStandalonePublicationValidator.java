package com.tungsten.depbot.publication;

import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.jenkins.JenkinsValidationService;
import com.tungsten.depbot.validation.FullBuildValidationGate;
import com.tungsten.depbot.validation.ValidationOutcome;
import com.tungsten.depbot.validation.ValidationRequest;

import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;

/**
 * The real {@link StandalonePublicationValidator}: checks out the isolated tree, runs the exact same
 * {@code mvn -B clean package} gate remediation itself uses, then the exact same Jenkins gate -- both
 * whole-tree checks that need no per-coordinate context, unlike the dependency-resolution gate, which this
 * deliberately does not re-run here (a passing full build already implies dependency resolution succeeded).
 * Restores the repository's original checkout afterward, success or failure, so publication never leaves
 * the shared working tree on an isolated publication branch.
 */
public final class MavenAndJenkinsStandalonePublicationValidator implements StandalonePublicationValidator {

    private final GitCommandRunner git;
    private final FullBuildValidationGate fullBuildGate;
    private final JenkinsValidationService jenkinsValidationService;

    public MavenAndJenkinsStandalonePublicationValidator(
            GitCommandRunner git, FullBuildValidationGate fullBuildGate,
            JenkinsValidationService jenkinsValidationService) {
        this.git = Objects.requireNonNull(git, "git");
        this.fullBuildGate = Objects.requireNonNull(fullBuildGate, "fullBuildGate");
        this.jenkinsValidationService = Objects.requireNonNull(jenkinsValidationService, "jenkinsValidationService");
    }

    @Override
    public Optional<String> revalidate(
            String runId, String unitId, Path repoPath, String verifiedSourceSha, String isolatedTip) {
        String originalHead;
        try {
            originalHead = git.currentHeadSha(repoPath);
        } catch (RuntimeException e) {
            return Optional.of("could not read the repository's current checkout before re-validation: "
                    + e.getMessage());
        }

        try {
            git.checkout(repoPath, isolatedTip);

            ValidationRequest request = new ValidationRequest(repoPath, "standalone-publication", "revalidation", null);
            ValidationOutcome buildOutcome = fullBuildGate.validate(request, () -> { });
            if (buildOutcome.status() != com.tungsten.depbot.validation.ValidationStatus.PASSED) {
                return Optional.of("the full build did not pass against the isolated tree: " + buildOutcome.reason());
            }

            JenkinsValidationOutcome jenkinsOutcome = jenkinsValidationService.validate(
                    runId, "publish-isolation__" + unitId, repoPath, verifiedSourceSha, isolatedTip);
            if (!jenkinsOutcome.succeeded()) {
                return Optional.of("Jenkins did not succeed against the isolated tree: " + jenkinsOutcome.status());
            }
            return Optional.empty();
        } catch (RuntimeException e) {
            return Optional.of("standalone re-validation could not complete: " + e.getMessage());
        } finally {
            try {
                git.checkout(repoPath, originalHead);
            } catch (RuntimeException e) {
                // Best-effort restoration only -- the caller's own reason (build/Jenkins failure, or the
                // exception already captured above) is what matters; a failure to restore the checkout
                // here must never mask it, and there is nothing more targeted to do about it than log by
                // way of the checked-out state itself being inspectable afterward.
            }
        }
    }
}
