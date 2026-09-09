package com.tungsten.depbot.git;

import java.util.List;

/** The result of one {@link RemediationDiffPolicy} check: allowed, or rejected with reasons. */
public record PolicyVerdict(boolean allowed, List<String> violations) {

    public PolicyVerdict {
        violations = violations == null ? List.of() : List.copyOf(violations);
    }

    public static PolicyVerdict passed() {
        return new PolicyVerdict(true, List.of());
    }

    public static PolicyVerdict rejected(List<String> violations) {
        return new PolicyVerdict(false, violations);
    }
}
