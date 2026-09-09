package com.tungsten.depbot.progress;

/**
 * The steps a single library goes through, at the granularity worth telling an operator about.
 *
 * <p>Finer than {@code RemediationStage}, which records how far a run got. A stage is a gate; a step is
 * something that takes time. The two Claude calls and the Maven gate can each run for minutes, and during
 * a manual pilot the difference between "it is thinking" and "it has hung" is the only thing anyone
 * watching actually wants to know.
 */
public enum RemediationStep {

    REFRESHING_REFS("refreshing remote refs"),
    REPOSITORY_REFRESH("resetting the checkout to the verified source ref"),
    ASSESSMENT("vulnerability analysis"),
    SOURCE_REF_VERIFICATION("verifying the source ref"),
    BRANCH_PREPARATION("preparing the remediation branch"),
    IMPLEMENTATION("implementation"),
    VALIDATION("local validation"),
    COMMIT_DECISION("commit or roll back"),
    FULL_BUILD_VALIDATION("full build validation"),
    JENKINS_VALIDATION("running the Jenkins WebApplicationDependencyValidation job; this can take a while"),
    HUMAN_REVIEW_CHECKOUT("checking out the reviewed commit"),
    HUMAN_REVIEW("human review"),
    RESTORE("restoring the checkout");

    private final String description;

    RemediationStep(String description) {
        this.description = description;
    }

    public String description() {
        return description;
    }
}
