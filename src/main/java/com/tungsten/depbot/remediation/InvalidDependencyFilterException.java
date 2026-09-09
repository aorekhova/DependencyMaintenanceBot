package com.tungsten.depbot.remediation;

/**
 * The {@code --dependency} value given to {@code remediate} is not a valid {@code groupId:artifactId}
 * pair. Thrown before anything else in the pilot run happens -- no scan, no plan read, no branch,
 * no Claude invocation.
 */
public class InvalidDependencyFilterException extends RuntimeException {

    public InvalidDependencyFilterException(String safeMessage) {
        super(safeMessage);
    }
}
