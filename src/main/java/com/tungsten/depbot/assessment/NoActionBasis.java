package com.tungsten.depbot.assessment;

/**
 * Why a {@code NO_ACTION_REQUIRED} conclusion is safe to accept, not merely asserted -- the only grounds
 * under which "nothing to do" is a genuinely settled answer, as opposed to one source's wording taken at
 * face value while a more authoritative one disagrees with it.
 *
 * <p>Required on every {@code NO_ACTION_REQUIRED} finding, and on no other conclusion --
 * {@link BatchAnalysisParser#validateFinding} fails the whole document closed both when it is missing
 * there and when it is set anywhere else. This alone does not judge whether the chosen value is actually
 * true for a given finding: establishing that -- including resolving a genuine version-range or
 * fixed-version contradiction between sources -- stays the Vulnerability Analysis Engineer's own
 * engineering judgement. This enum only makes that judgement machine-readable enough to enforce that one
 * was actually reached, never what it should have been.
 */
public enum NoActionBasis {

    /** The coordinate is not present anywhere this analysis examined -- there is nothing to remediate. */
    DEPENDENCY_NOT_PRESENT,

    /** The dependency is present, and no released version fixes the vulnerability at all. */
    NO_FIXED_VERSION_EXISTS,

    /**
     * The dependency is present, a released fixed version exists, and the version genuinely in effect
     * here already meets or exceeds it. A fixed version existing but not yet applied is not this --
     * that is a remediation to carry out, not a reason to conclude nothing is required.
     */
    ALREADY_AT_OR_ABOVE_FIXED_VERSION
}
