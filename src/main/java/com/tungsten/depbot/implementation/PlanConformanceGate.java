package com.tungsten.depbot.implementation;

import com.tungsten.depbot.assessment.AnalysisRemediationGroup;
import com.tungsten.depbot.assessment.PlannedChangeType;
import com.tungsten.depbot.assessment.PlannedDependencyChange;
import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.remediation.RejectionStage;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Java-owned, structural re-check that an implementation's actual, final POM state matches its approved
 * plan's machine-readable {@link PlannedDependencyChange} entries -- run in two phases inside
 * {@link RemediationImplementationService#implement}, never in one call, because some cases (a value
 * reachable only through an external, not-locally-present parent or BOM) cannot be conclusively resolved
 * from this repository's own files alone -- Maven's own dependency-resolution gate has already done that
 * resolution externally, and this class reuses its answer rather than hand-rolling a full Maven model.
 *
 * <p>{@code approvedPlan} is the group's own {@link AnalysisRemediationGroup} -- the Vulnerability
 * Analysis Engineer's plan, including its machine-readable {@code plannedChanges} -- never a separately
 * approved draft; there is no Planner/Plan Reviewer stage between analysis and implementation.
 *
 * <p><strong>Phase A ({@link #checkStructural})</strong> checks file scope for every {@code
 * plannedChanges} entry against the pre-commit diff (this codebase commits only after its local gates
 * already ran), then checks {@code DEPENDENCY_MANAGEMENT_ADDITION}/{@code EXCLUSION_ADDED}/{@code
 * VERSION_BUMP} against the repository's own, current final POM tree -- every {@code pom.xml} under the
 * workspace, never only the ones a git diff happens to touch, since a legitimate remediation may bump a
 * property or BOM version in one file while the module that actually consumes it (unchanged text, same
 * effective value either way) lives in a different file entirely. Property/{@code dependencyManagement}/
 * imported-BOM resolution is always scoped to the specific POM a declaration was found in, plus its own
 * local {@code <parent>} chain (see {@link RepositoryPomIndex}) -- never a same-named property or an
 * unrelated sibling module's management entry. {@code VERSION_BUMP} supports both an ordinary
 * {@code <dependency>} and an existing {@code dependencyManagement} entry (an imported BOM included --
 * {@code type=pom scope=import} is never a distinct case, since it is simply a {@code dependency} element
 * that happens to carry those two children) with no direct consumer anywhere; whichever one actually
 * exists for the planned coordinates decides which path resolves it, never the plan itself. A managed
 * entry that did not already exist at {@code baselineSha} fails closed rather than being accepted as a
 * version bump of something that was, in truth, just added -- that shape belongs to
 * {@code DEPENDENCY_MANAGEMENT_ADDITION} instead. A resolved value that already matched the plan's target
 * at {@code baselineSha} too is flagged as a no-op, not silently accepted. {@code OTHER} is never checked for
 * conformance at all -- it exists precisely for changes Java cannot objectively verify, so every {@code
 * OTHER} entry is recorded as an informational {@link PlanConformanceResult#unverifiableNotes()} entry
 * instead; a group whose plan contains {@code OTHER} is routed to the risky singleton path by {@code
 * AnalysisRemediationGroup#requiresRiskyRouting()} well before Implementation ever runs, which is where
 * that carries consequence, not here. A value reachable only through an external parent/BOM this
 * repository's own files cannot prove is returned as {@link PhaseAResult#pendingVersionChecks()}, never
 * guessed at.
 *
 * <p><strong>Phase B ({@link #checkResolvedVersions})</strong> runs only when Phase A left pending
 * entries, reusing the dependency-resolution gate's own already-computed per-coordinate resolved-version
 * evidence -- no second Maven invocation.
 */
public final class PlanConformanceGate {

    private static final Pattern DIFF_FILE_HEADER = Pattern.compile("^diff --git a/(.+) b/(.+)$", Pattern.MULTILINE);
    private static final int MAX_PARENT_CHAIN_DEPTH = 10;

    private PlanConformanceGate() {
    }

    /** Phase A's own output: the immediate verdict, plus any {@code VERSION_BUMP} entries still pending. */
    public record PhaseAResult(PlanConformanceResult result, List<PlannedDependencyChange> pendingVersionChecks) {
        public PhaseAResult {
            pendingVersionChecks = pendingVersionChecks == null ? List.of() : List.copyOf(pendingVersionChecks);
        }
    }

    public static PhaseAResult checkStructural(
            GitCommandRunner git, Path workspace, String baselineSha, AnalysisRemediationGroup approvedPlan) {
        return checkStructural(git, workspace, baselineSha, approvedPlan, null);
    }

    /**
     * As the 4-arg overload, but on a retry ({@code repairContext != null}) an otherwise-unauthorized file
     * may be accepted as a narrow, evidence-linked scope extension instead of an outright violation -- see
     * {@link #checkScopeExtension} for the per-stage rules. {@code repairContext} is {@code null} for
     * attempt 1 of every group, so this overload behaves identically to the 4-arg one in that case.
     */
    public static PhaseAResult checkStructural(
            GitCommandRunner git, Path workspace, String baselineSha, AnalysisRemediationGroup approvedPlan,
            RepairContext repairContext) {
        // A plain "git diff <sha>" never shows a brand-new untracked file at all -- marking every
        // untracked path's presence first (metadata only, exactly as AttemptedChangeCapture already
        // relies on) makes an entirely new, out-of-scope file show up in the diff as a real addition,
        // so the file-scope check below cannot be silently bypassed by adding a new file instead of
        // editing an existing one.
        git.markIntentToAddAll(workspace);
        String diff = git.diffAgainst(workspace, baselineSha);
        Set<String> changedFiles = changedFilePaths(diff);

        List<String> violations = new ArrayList<>();
        List<String> unverifiableNotes = new ArrayList<>();
        List<String> scopeExtensions = new ArrayList<>();
        List<PlannedDependencyChange> pending = new ArrayList<>();

        Set<String> allowedFiles = new LinkedHashSet<>(approvedPlan.affectedFiles());
        for (PlannedDependencyChange change : approvedPlan.plannedChanges()) {
            allowedFiles.add(change.affectedFile());
        }
        for (String changedFile : changedFiles) {
            if (allowedFiles.contains(changedFile)) {
                continue;
            }
            ScopeExtensionResult extension = repairContext == null
                    ? ScopeExtensionResult.rejected()
                    : checkScopeExtension(git, workspace, baselineSha, changedFile, approvedPlan, repairContext);
            if (extension.accepted()) {
                scopeExtensions.add(extension.detail());
            } else {
                violations.add("unauthorized file changed: " + changedFile);
            }
        }

        // Every pom.xml this repository actually has -- never only the ones this diff happens to touch.
        // A legitimate remediation may change a property/BOM version in one file while the module that
        // actually consumes it (same text either way) lives in a different, untouched file entirely.
        List<String> pomFiles = allPomFiles(workspace);

        for (PlannedDependencyChange change : approvedPlan.plannedChanges()) {
            switch (change.changeType()) {
                case DEPENDENCY_MANAGEMENT_ADDITION -> {
                    String violation = dependencyManagementViolation(git, workspace, baselineSha, pomFiles, change);
                    if (violation != null) {
                        violations.add(violation);
                    }
                }
                case EXCLUSION_ADDED -> {
                    String violation = exclusionViolation(workspace, pomFiles, change);
                    if (violation != null) {
                        violations.add(violation);
                    }
                }
                case VERSION_BUMP -> {
                    VersionCheckResult versionCheck = checkVersionBump(git, workspace, baselineSha, pomFiles, change);
                    switch (versionCheck.kind()) {
                        case CONFORMS -> { }
                        case VIOLATION -> violations.add(versionCheck.detail());
                        case PENDING -> pending.add(change);
                    }
                }
                case OTHER -> unverifiableNotes.add("planned change for " + change.dependencyCoordinates()
                        + " has changeType OTHER (\"" + change.reason() + "\") -- Java cannot objectively "
                        + "verify this kind of change, so it is not checked for conformance and never "
                        + "counted as a violation; the group is routed to human review through the risky "
                        + "singleton path for exactly this reason");
            }
        }

        return new PhaseAResult(
                new PlanConformanceResult(violations.isEmpty(), violations, unverifiableNotes, scopeExtensions),
                pending);
    }

    // ---- failure-driven, narrow, per-stage scope extension (retry only) ---------------------------

    private record ScopeExtensionResult(boolean accepted, String detail) {
        static ScopeExtensionResult accepted(String detail) {
            return new ScopeExtensionResult(true, detail);
        }

        static ScopeExtensionResult rejected() {
            return new ScopeExtensionResult(false, null);
        }
    }

    /**
     * Whether {@code changedFile} -- otherwise unauthorized -- may be accepted on this retry as a narrow,
     * mechanically-checkable response to {@code repairContext}'s own machine-owned failure evidence. Each
     * stage below has its own independent rule; a stage with no rule here always falls through to
     * {@link ScopeExtensionResult#rejected()} -- there is no generic "attempt 2 may touch anything" path.
     * Never authorizes a target/version/strategy change: every originally-authorized file still goes
     * through this same method's caller's unchanged per-{@code plannedChanges} checks regardless of what
     * happens here.
     */
    private static ScopeExtensionResult checkScopeExtension(
            GitCommandRunner git, Path workspace, String baselineSha, String changedFile,
            AnalysisRemediationGroup approvedPlan, RepairContext repairContext) {
        return switch (repairContext.failedStage()) {
            case DEPENDENCY_VALIDATION -> checkNarrowExclusionOnlyExtension(
                    git, workspace, baselineSha, changedFile, approvedPlan);
            case PLAN_DEVIATION_REQUIRED -> checkDiscoveredControlPointExtension(workspace, changedFile, approvedPlan)
                    ? ScopeExtensionResult.accepted("attempt " + repairContext.failedStage()
                            + ": " + changedFile + " is this coordinate's own, mechanically-discovered real "
                            + "control point")
                    : ScopeExtensionResult.rejected();
            case FULL_BUILD, CUMULATIVE_JENKINS -> checkEvidenceNamedFileExtension(
                    git, workspace, baselineSha, changedFile, approvedPlan, repairContext);
            default -> ScopeExtensionResult.rejected();
        };
    }

    /**
     * {@code DEPENDENCY_VALIDATION} evidence (the json-lib case): the file must already have existed at
     * baseline, its final state must be structurally identical to baseline except for added
     * {@code <exclusion>} elements (never a removed one, never any other structural change), and every
     * newly-added exclusion must target a coordinate {@code approvedPlan} already names as a member --
     * never an unrelated coordinate.
     */
    private static ScopeExtensionResult checkNarrowExclusionOnlyExtension(
            GitCommandRunner git, Path workspace, String baselineSha, String changedFile,
            AnalysisRemediationGroup approvedPlan) {
        Document baseline = new BaselinePomSource(git, workspace, baselineSha).documentAt(changedFile);
        Document finalDoc = new FilesystemPomSource(workspace).documentAt(changedFile);
        if (baseline == null || finalDoc == null) {
            return ScopeExtensionResult.rejected();
        }
        if (!canonicalizeIgnoringExclusions(baseline.getDocumentElement())
                .equals(canonicalizeIgnoringExclusions(finalDoc.getDocumentElement()))) {
            return ScopeExtensionResult.rejected();
        }

        Set<String> baselineExclusions = exclusionCoordinates(baseline);
        Set<String> finalExclusions = exclusionCoordinates(finalDoc);
        if (!finalExclusions.containsAll(baselineExclusions)) {
            return ScopeExtensionResult.rejected();
        }
        Set<String> added = new LinkedHashSet<>(finalExclusions);
        added.removeAll(baselineExclusions);
        if (added.isEmpty()) {
            return ScopeExtensionResult.rejected();
        }
        for (String coordinate : added) {
            if (!approvedPlan.memberCoordinates().contains(coordinate)) {
                return ScopeExtensionResult.rejected();
            }
        }
        return ScopeExtensionResult.accepted("DEPENDENCY_VALIDATION retry: " + changedFile
                + " gained exclusion(s) for " + String.join(", ", added)
                + " -- the exact coordinate(s) this remediation targets, closing a transitive path the "
                + "original plan did not cover");
    }

    /** A canonical string form of {@code element}, with every {@code <exclusion>} subtree treated as
     *  invisible -- so adding/removing exclusions never affects equality, but any other structural change
     *  (a version, a new dependency, a reordered/renamed element) does. */
    private static String canonicalizeIgnoringExclusions(Node node) {
        if (node.getNodeType() == Node.TEXT_NODE || node.getNodeType() == Node.CDATA_SECTION_NODE) {
            String text = node.getTextContent();
            return text == null ? "" : text.strip();
        }
        if (node.getNodeType() != Node.ELEMENT_NODE) {
            return "";
        }
        Element element = (Element) node;
        if ("exclusion".equals(element.getTagName()) || "exclusions".equals(element.getTagName())) {
            // The wrapper element only ever holds <exclusion> children, so it is just as invisible to
            // this comparison as the exclusions themselves -- otherwise an <exclusions> block appearing
            // only in the final state (empty once its own <exclusion> children are suppressed) would
            // register as a spurious structural difference from a baseline that never had one at all.
            return "";
        }
        StringBuilder canonical = new StringBuilder("<").append(element.getTagName());
        NamedNodeMap attributes = element.getAttributes();
        List<String> attributeStrings = new ArrayList<>();
        for (int i = 0; i < attributes.getLength(); i++) {
            Node attribute = attributes.item(i);
            attributeStrings.add(attribute.getNodeName() + "=" + attribute.getNodeValue());
        }
        Collections.sort(attributeStrings);
        for (String attribute : attributeStrings) {
            canonical.append(' ').append(attribute);
        }
        canonical.append('>');
        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            canonical.append(canonicalizeIgnoringExclusions(children.item(i)));
        }
        canonical.append("</").append(element.getTagName()).append('>');
        return canonical.toString();
    }

    private static Set<String> exclusionCoordinates(Document doc) {
        Set<String> result = new LinkedHashSet<>();
        NodeList exclusions = doc.getElementsByTagName("exclusion");
        for (int i = 0; i < exclusions.getLength(); i++) {
            Element exclusion = (Element) exclusions.item(i);
            String groupId = childText(exclusion, "groupId");
            String artifactId = childText(exclusion, "artifactId");
            if (groupId != null && artifactId != null) {
                result.add(groupId + ":" + artifactId);
            }
        }
        return result;
    }

    /**
     * {@code PLAN_DEVIATION_REQUIRED} evidence: {@code changedFile} is accepted only if this class's own
     * independent POM discovery -- never Claude's claim -- proves it is the real control point (a direct
     * {@code <dependency>} declaration, or an applicable {@code dependencyManagement} entry) for a
     * coordinate {@code approvedPlan} already plans a {@code VERSION_BUMP}/{@code DEPENDENCY_MANAGEMENT_ADDITION}
     * for. The declared target for that coordinate must still match the plan exactly -- checked identically
     * to any authorized file, via this same method's caller's ordinary per-{@code plannedChanges} loop.
     */
    private static boolean checkDiscoveredControlPointExtension(
            Path workspace, String changedFile, AnalysisRemediationGroup approvedPlan) {
        RepositoryPomIndex finalIndex = new RepositoryPomIndex(new FilesystemPomSource(workspace));
        for (PlannedDependencyChange change : approvedPlan.plannedChanges()) {
            if (change.changeType() != PlannedChangeType.VERSION_BUMP
                    && change.changeType() != PlannedChangeType.DEPENDENCY_MANAGEMENT_ADDITION) {
                continue;
            }
            String[] coordinates = splitCoordinates(change.dependencyCoordinates());
            Document doc = finalIndex.documentAt(changedFile);
            if (doc == null) {
                continue;
            }
            if (findDependencyElement(doc, coordinates[0], coordinates[1], false) != null) {
                return true;
            }
            if (findApplicableDependencyManagement(changedFile, finalIndex, coordinates) != null) {
                return true;
            }
        }
        return false;
    }

    /**
     * {@code FULL_BUILD}/{@code CUMULATIVE_JENKINS} evidence: {@code changedFile} must already have
     * existed at baseline (a brand-new file is never accepted this way) and its full, normalized relative
     * path must appear verbatim in the machine-produced failure evidence text -- never a bare filename
     * match, never merely Claude's own assertion. A recognized Maven POM file gets no free pass for its
     * Maven content just because its path was logged: it must additionally satisfy either the
     * exclusion-only or the discovered-control-point rule above. A non-POM file (a genuine source/config
     * compatibility file) is accepted without inspecting its content -- no Java-side semantic analysis of
     * source code -- but the caller must route the resulting success exactly like a genuine
     * {@code HUMAN_REVIEW_REQUIRED} group, never merely label it after the fact (see
     * {@link ScopeExtensionResult#detail()}'s {@code forcesHumanReview} marker prefix).
     */
    private static ScopeExtensionResult checkEvidenceNamedFileExtension(
            GitCommandRunner git, Path workspace, String baselineSha, String changedFile,
            AnalysisRemediationGroup approvedPlan, RepairContext repairContext) {
        if (git.showFileAt(workspace, baselineSha, changedFile) == null) {
            return ScopeExtensionResult.rejected();
        }
        String evidenceText = evidenceTextFor(repairContext);
        if (evidenceText == null || !evidenceText.contains(changedFile)) {
            return ScopeExtensionResult.rejected();
        }

        boolean isPom = changedFile.endsWith("pom.xml");
        if (isPom) {
            ScopeExtensionResult exclusionOnly =
                    checkNarrowExclusionOnlyExtension(git, workspace, baselineSha, changedFile, approvedPlan);
            if (exclusionOnly.accepted()) {
                return exclusionOnly;
            }
            return checkDiscoveredControlPointExtension(workspace, changedFile, approvedPlan)
                    ? ScopeExtensionResult.accepted(repairContext.failedStage() + " retry: " + changedFile
                            + " is named in the failure evidence and is a mechanically-discovered real "
                            + "control point")
                    : ScopeExtensionResult.rejected();
        }
        return ScopeExtensionResult.accepted("FORCES_HUMAN_REVIEW " + repairContext.failedStage()
                + " retry: " + changedFile + " is a non-Maven compatibility file explicitly named in the "
                + "machine-produced failure evidence -- accepted without inspecting its content, but this "
                + "group must be routed exactly like a genuine HUMAN_REVIEW_REQUIRED group, never "
                + "auto-merge-eligible");
    }

    private static String evidenceTextFor(RepairContext repairContext) {
        StringBuilder text = new StringBuilder();
        if (repairContext.fullBuildValidationOutcome() != null) {
            text.append(nullToEmpty(repairContext.fullBuildValidationOutcome().reason())).append('\n');
            text.append(nullToEmpty(repairContext.fullBuildValidationOutcome().output())).append('\n');
        }
        if (repairContext.jenkinsConsoleLogExcerpt() != null) {
            text.append(repairContext.jenkinsConsoleLogExcerpt());
        }
        return text.length() == 0 ? null : text.toString();
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    /** Phase B: confirms every still-pending {@code VERSION_BUMP} against already-resolved evidence. */
    public static PlanConformanceResult checkResolvedVersions(
            List<PlannedDependencyChange> pendingVersionChecks, Map<String, String> resolvedVersionsByCoordinates) {
        List<String> violations = new ArrayList<>();
        for (PlannedDependencyChange change : pendingVersionChecks) {
            String resolved = resolvedVersionsByCoordinates.get(change.dependencyCoordinates());
            if (resolved == null) {
                violations.add("no resolved-version evidence found for " + change.dependencyCoordinates()
                        + " (planned target version " + change.targetVersion() + ")");
            } else if (!resolved.equals(change.targetVersion())) {
                violations.add(change.dependencyCoordinates() + " actually resolved to " + resolved
                        + " but the approved plan specified target version " + change.targetVersion());
            }
        }
        return new PlanConformanceResult(violations.isEmpty(), violations, List.of());
    }

    /**
     * Whether {@code declaringFile}'s own local {@code <parent>} chain currently has a direct
     * {@code <dependency>} declaration for {@code coordinates} -- the same, scoped discovery
     * {@link #checkVersionBump} uses to decide whether a {@code VERSION_BUMP} targets an ordinary
     * dependency or falls back to the management-only path, exposed here so a caller outside this class
     * (the Vulnerability Analysis Engineer's own structured-output consistency check, run before
     * Implementation ever sees the plan) can ask the identical question against the current working tree
     * rather than re-implementing Maven-aware POM discovery.
     */
    public static boolean hasDirectDependency(Path workspace, String declaringFile, String coordinates) {
        RepositoryPomIndex index = new RepositoryPomIndex(new FilesystemPomSource(workspace));
        Document doc = index.documentAt(declaringFile);
        if (doc == null) {
            return false;
        }
        String[] parts = splitCoordinates(coordinates);
        return findDependencyElement(doc, parts[0], parts[1], false) != null;
    }

    /**
     * Whether an effective {@code dependencyManagement}/BOM entry for {@code coordinates} already exists,
     * scoped to exactly {@code declaringFile} and its own local {@code <parent>} chain, in the current
     * working tree -- the same question {@link #checkVersionBumpAgainstManagedEntry} answers against a
     * git baseline SHA, exposed here for the same reason as {@link #hasDirectDependency}.
     */
    public static boolean hasEffectiveManagedEntry(Path workspace, String declaringFile, String coordinates) {
        RepositoryPomIndex index = new RepositoryPomIndex(new FilesystemPomSource(workspace));
        return findApplicableDependencyManagement(declaringFile, index, splitCoordinates(coordinates)) != null;
    }

    /** Combines Phase A's and Phase B's violations and unverifiable notes into one final verdict. */
    public static PlanConformanceResult merge(PlanConformanceResult phaseA, PlanConformanceResult phaseB) {
        List<String> violations = new ArrayList<>(phaseA.violations());
        violations.addAll(phaseB.violations());
        List<String> unverifiableNotes = new ArrayList<>(phaseA.unverifiableNotes());
        unverifiableNotes.addAll(phaseB.unverifiableNotes());
        List<String> scopeExtensions = new ArrayList<>(phaseA.scopeExtensions());
        scopeExtensions.addAll(phaseB.scopeExtensions());
        return new PlanConformanceResult(violations.isEmpty(), violations, unverifiableNotes, scopeExtensions);
    }

    // ---- file scope -----------------------------------------------------------------------------

    private static Set<String> changedFilePaths(String diff) {
        Set<String> paths = new LinkedHashSet<>();
        if (diff == null || diff.isBlank()) {
            return paths;
        }
        Matcher matcher = DIFF_FILE_HEADER.matcher(diff);
        while (matcher.find()) {
            paths.add(matcher.group(2));
        }
        return paths;
    }

    // ---- discovery: every pom.xml this repository has, not only the changed ones -----------------

    private static List<String> allPomFiles(Path workspace) {
        try (Stream<Path> stream = Files.walk(workspace)) {
            return stream
                    .filter(p -> p.getFileName().toString().equals("pom.xml"))
                    .map(p -> workspace.relativize(p).toString().replace('\\', '/'))
                    .filter(rel -> !hasExcludedSegment(rel))
                    .sorted()
                    .toList();
        } catch (IOException e) {
            return List.of();
        }
    }

    /**
     * Segment-aware exclusion of build output ({@code target}) and VCS internals ({@code .git}) -- a
     * whole path segment, never a substring match, so a real module directory named e.g. {@code
     * "retarget"} is never mistaken for Maven's own {@code target} directory.
     */
    private static boolean hasExcludedSegment(String relativePosixPath) {
        for (String segment : relativePosixPath.split("/")) {
            if (segment.equals("target") || segment.equals(".git")) {
                return true;
            }
        }
        return false;
    }

    // ---- POM content, from either the live filesystem or a fixed git commit ----------------------

    /** Parsed content of the pom.xml at a repo-relative path, or {@code null} if it does not exist there. */
    private interface PomSource {
        Document documentAt(String repoRelativePath);
    }

    private static final class FilesystemPomSource implements PomSource {
        private final Path workspace;

        FilesystemPomSource(Path workspace) {
            this.workspace = workspace;
        }

        @Override
        public Document documentAt(String repoRelativePath) {
            Path file = workspace.resolve(repoRelativePath);
            return Files.exists(file) ? parseXml(file) : null;
        }
    }

    private static final class BaselinePomSource implements PomSource {
        private final GitCommandRunner git;
        private final Path workspace;
        private final String baselineSha;

        BaselinePomSource(GitCommandRunner git, Path workspace, String baselineSha) {
            this.git = git;
            this.workspace = workspace;
            this.baselineSha = baselineSha;
        }

        @Override
        public Document documentAt(String repoRelativePath) {
            String content = git.showFileAt(workspace, baselineSha, repoRelativePath);
            return content == null ? null : parseXmlFromString(content);
        }
    }

    /**
     * Which pom.xml files exist per one {@link PomSource}, and how to walk a POM's own local {@code
     * <parent>} chain within it -- never a property/dependencyManagement lookup that wanders into an
     * unrelated module. A {@code <parent>} whose {@code relativePath} does not resolve to a file this
     * source actually has is external: the chain stops there, and whatever depends on climbing further is
     * left unresolved for {@link #checkResolvedVersions} (the real Maven invocation) to decide.
     */
    private static final class RepositoryPomIndex {
        private final PomSource source;

        RepositoryPomIndex(PomSource source) {
            this.source = source;
        }

        Document documentAt(String path) {
            return source.documentAt(path);
        }

        /** This POM's own local parent path, or {@code null} (no {@code <parent>}, an explicit empty
         *  {@code relativePath}, or the referenced file is not present in this source). */
        String localParentOf(String path, Document doc) {
            Element parent = directChildElement(doc.getDocumentElement(), "parent");
            if (parent == null) {
                return null;
            }
            String relativePath = childText(parent, "relativePath");
            if (relativePath != null && relativePath.isBlank()) {
                return null; // explicit opt-out, per Maven convention
            }
            String candidate = resolveRelative(path, relativePath == null ? "../pom.xml" : relativePath);
            return source.documentAt(candidate) != null ? candidate : null;
        }
    }

    private static String resolveRelative(String basePath, String relativePath) {
        Path base = Path.of(basePath).getParent();
        Path resolved = (base == null ? Path.of(relativePath) : base.resolve(relativePath)).normalize();
        String result = resolved.toString().replace('\\', '/');
        if (!result.endsWith("pom.xml")) {
            result = result.isEmpty() ? "pom.xml" : result + "/pom.xml";
        }
        return result;
    }

    // ---- scoped property / version resolution -- owning POM + its own local parent chain only -----

    private static String propertyFromDocument(Document doc, String propertyName) {
        NodeList propertyBlocks = doc.getElementsByTagName("properties");
        for (int i = 0; i < propertyBlocks.getLength(); i++) {
            String value = childText((Element) propertyBlocks.item(i), propertyName);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    /**
     * Resolves {@code ${propertyName}} starting at exactly {@code startPath}, then its own local parent
     * chain (bounded depth against a cycle) -- never a same-named property defined in an unrelated
     * module. {@code null} if not found anywhere in the locally-known chain -- it may come from an
     * external parent this index cannot see; {@link #checkResolvedVersions} is the authority for that.
     */
    private static String resolveProperty(String startPath, RepositoryPomIndex index, String propertyName) {
        String current = startPath;
        int depth = 0;
        while (current != null && depth++ < MAX_PARENT_CHAIN_DEPTH) {
            Document doc = index.documentAt(current);
            if (doc == null) {
                return null;
            }
            String value = propertyFromDocument(doc, propertyName);
            if (value != null) {
                return value;
            }
            current = index.localParentOf(current, doc);
        }
        return null;
    }

    /** Literal text as-is; a {@code ${property}} reference resolved from exactly {@code startPath}'s own
     *  local chain. */
    private static String resolveVersionText(String startPath, RepositoryPomIndex index, String versionText) {
        if (!(versionText.startsWith("${") && versionText.endsWith("}"))) {
            return versionText;
        }
        return resolveProperty(startPath, index, versionText.substring(2, versionText.length() - 1));
    }

    /**
     * A {@code dependencyManagement} entry for {@code coordinates}, applicable to exactly this owning
     * POM: its own {@code dependencyManagement} block, then its local parent chain -- never a
     * sibling/unrelated module's entry, however coincidentally matching.
     */
    private static Element findApplicableDependencyManagement(
            String owningPath, RepositoryPomIndex index, String[] coordinates) {
        String current = owningPath;
        int depth = 0;
        while (current != null && depth++ < MAX_PARENT_CHAIN_DEPTH) {
            Document doc = index.documentAt(current);
            if (doc == null) {
                return null;
            }
            Element managed = findDependencyElement(doc, coordinates[0], coordinates[1], true);
            if (managed != null) {
                return managed;
            }
            current = index.localParentOf(current, doc);
        }
        return null;
    }

    /**
     * Is there an imported BOM ({@code scope=import}, {@code type=pom}) reachable from exactly this
     * owning POM's own local parent chain -- never "anywhere in the repository." Used only to decide
     * whether an otherwise-unresolvable value is plausibly owned by an EXTERNAL BOM (defer to Phase B) or
     * is genuinely unexplained locally (fail closed).
     */
    private static boolean hasApplicableBomImport(String owningPath, RepositoryPomIndex index) {
        String current = owningPath;
        int depth = 0;
        while (current != null && depth++ < MAX_PARENT_CHAIN_DEPTH) {
            Document doc = index.documentAt(current);
            if (doc == null) {
                return false;
            }
            if (hasBomImport(doc)) {
                return true;
            }
            current = index.localParentOf(current, doc);
        }
        return false;
    }

    private static boolean hasBomImport(Document doc) {
        NodeList dependencies = doc.getElementsByTagName("dependency");
        for (int i = 0; i < dependencies.getLength(); i++) {
            Element dependency = (Element) dependencies.item(i);
            if ("import".equals(childText(dependency, "scope")) && "pom".equals(childText(dependency, "type"))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Is there a genuine {@code <parent>} reference, anywhere in {@code startPath}'s own local chain,
     * that this index cannot actually read the content of -- a real external parent (fetched from a
     * remote repository, not present as a file in this checkout) rather than simply having no parent at
     * all. That is a plausible boundary worth deferring to Phase B's real Maven invocation (which reads
     * external parents Java cannot see here); a chain that dead-ends with no {@code <parent>} element at
     * all explains nothing and is not such a boundary.
     */
    private static boolean hasExternalParentBoundary(String startPath, RepositoryPomIndex index) {
        String current = startPath;
        int depth = 0;
        while (current != null && depth++ < MAX_PARENT_CHAIN_DEPTH) {
            Document doc = index.documentAt(current);
            if (doc == null) {
                return false;
            }
            Element parent = directChildElement(doc.getDocumentElement(), "parent");
            if (parent != null) {
                String relativePath = childText(parent, "relativePath");
                boolean explicitOptOut = relativePath != null && relativePath.isBlank();
                if (!explicitOptOut) {
                    String candidate = resolveRelative(current, relativePath == null ? "../pom.xml" : relativePath);
                    if (index.documentAt(candidate) == null) {
                        return true;
                    }
                }
            }
            current = index.localParentOf(current, doc);
        }
        return false;
    }

    /** Resolved (with a value), deferred (a plausible external boundary exists), or unresolvable
     *  (nothing local proves a value, and no plausible external boundary either). */
    private record EffectiveVersion(String value, boolean deferToPhaseB) {
        static EffectiveVersion resolved(String value) {
            return new EffectiveVersion(value, false);
        }

        static EffectiveVersion deferred() {
            return new EffectiveVersion(null, true);
        }

        static EffectiveVersion unresolvable() {
            return new EffectiveVersion(null, false);
        }
    }

    /**
     * The effective version this exact owning POM's own direct {@code <dependency>} for {@code
     * coordinates} actually has, per this one index (either the live filesystem or a baseline git-show
     * view) -- literal, local-property-resolved, or (versionless) resolved through an applicable local
     * {@code dependencyManagement} entry. Unresolvable when the owning POM does not have this view of the
     * dependency at all (e.g. it did not exist yet at baseline) or when its own chain cannot prove a
     * value with no plausible external boundary either; deferred when a plausible external BOM/parent
     * boundary exists locally.
     */
    private static EffectiveVersion resolveEffectivePlannedVersion(
            String owningPath, RepositoryPomIndex index, String[] coordinates) {
        Document doc = index.documentAt(owningPath);
        if (doc == null) {
            return EffectiveVersion.unresolvable();
        }
        Element direct = findDependencyElement(doc, coordinates[0], coordinates[1], false);
        if (direct == null) {
            return EffectiveVersion.unresolvable();
        }
        String versionText = childText(direct, "version");
        if (versionText != null && !versionText.isBlank()) {
            String resolved = resolveVersionText(owningPath, index, versionText);
            return resolved != null ? EffectiveVersion.resolved(resolved) : EffectiveVersion.deferred();
        }
        Element managed = findApplicableDependencyManagement(owningPath, index, coordinates);
        if (managed != null) {
            String managedText = childText(managed, "version");
            String resolved = managedText == null || managedText.isBlank()
                    ? null : resolveVersionText(owningPath, index, managedText);
            return resolved != null ? EffectiveVersion.resolved(resolved) : EffectiveVersion.deferred();
        }
        return hasApplicableBomImport(owningPath, index) || hasExternalParentBoundary(owningPath, index)
                ? EffectiveVersion.deferred() : EffectiveVersion.unresolvable();
    }

    /**
     * The effective version an applicable {@code dependencyManagement} entry for {@code coordinates}
     * gives, scoped to exactly {@code declaringPath} + its own local parent chain. Unlike {@link
     * #resolveEffectivePlannedVersion}, this never requires a direct {@code <dependency>} to exist for
     * the same coordinates anywhere -- a {@code DEPENDENCY_MANAGEMENT_ADDITION} entry is legitimately the
     * thing being asserted, and can exist ahead of any consumer needing it.
     */
    private static EffectiveVersion resolveEffectiveManagedVersion(
            String declaringPath, RepositoryPomIndex index, String[] coordinates) {
        Element managed = findApplicableDependencyManagement(declaringPath, index, coordinates);
        if (managed == null) {
            return EffectiveVersion.unresolvable();
        }
        String versionText = childText(managed, "version");
        if (versionText == null || versionText.isBlank()) {
            return EffectiveVersion.unresolvable();
        }
        String resolved = resolveVersionText(declaringPath, index, versionText);
        return resolved != null ? EffectiveVersion.resolved(resolved) : EffectiveVersion.deferred();
    }

    // ---- VERSION_BUMP -----------------------------------------------------------------------------

    private enum VersionCheckKind { CONFORMS, VIOLATION, PENDING }

    private record VersionCheckResult(VersionCheckKind kind, String detail) {
        static VersionCheckResult conforms() {
            return new VersionCheckResult(VersionCheckKind.CONFORMS, null);
        }

        static VersionCheckResult violation(String detail) {
            return new VersionCheckResult(VersionCheckKind.VIOLATION, detail);
        }

        static VersionCheckResult pending() {
            return new VersionCheckResult(VersionCheckKind.PENDING, null);
        }
    }

    /** Discovery only: the repo-relative path of the first pom.xml (in {@code pomFiles}) with a direct
     *  {@code <dependency>} for {@code coordinates}, whatever its version state -- global, since the
     *  consuming module could be anywhere in the reactor. {@code null} if none has one at all. */
    private static String discoverOwningPom(List<String> pomFiles, RepositoryPomIndex index, String[] coordinates) {
        for (String path : pomFiles) {
            Document doc = index.documentAt(path);
            if (doc == null) {
                continue;
            }
            if (findDependencyElement(doc, coordinates[0], coordinates[1], false) != null) {
                return path;
            }
        }
        return null;
    }

    /**
     * A {@code VERSION_BUMP} may bump the version of either an ordinary {@code <dependency>} or an
     * existing {@code dependencyManagement} entry (including an imported BOM, {@code type=pom
     * scope=import}) -- the coordinates being a plain dependency somewhere or a management-only entry
     * (a BOM is never declared any other way) decides which, not the plan itself. An ordinary dependency
     * takes priority when both exist, since {@link #resolveEffectivePlannedVersion} already follows a
     * versionless one through to its own applicable management entry -- the management-only path below is
     * reached only when no direct {@code <dependency>} exists anywhere, which is exactly the shape of a
     * BOM or a library nothing in this repository consumes directly yet.
     */
    private static VersionCheckResult checkVersionBump(
            GitCommandRunner git, Path workspace, String baselineSha, List<String> pomFiles,
            PlannedDependencyChange change) {
        String[] coordinates = splitCoordinates(change.dependencyCoordinates());
        RepositoryPomIndex finalIndex = new RepositoryPomIndex(new FilesystemPomSource(workspace));

        String owningPath = discoverOwningPom(pomFiles, finalIndex, coordinates);
        if (owningPath != null) {
            return checkVersionBumpAgainstDirectDependency(git, workspace, baselineSha, change, coordinates,
                    finalIndex, owningPath);
        }

        String declaringPath = discoverManagementEntry(pomFiles, finalIndex, coordinates);
        if (declaringPath != null) {
            return checkVersionBumpAgainstManagedEntry(git, workspace, baselineSha, change, coordinates,
                    finalIndex, declaringPath);
        }

        return VersionCheckResult.violation("no <dependency> declaration for " + change.dependencyCoordinates()
                + " found anywhere in this repository's POM files, and no dependencyManagement/BOM "
                + "entry for it either");
    }

    private static VersionCheckResult checkVersionBumpAgainstDirectDependency(
            GitCommandRunner git, Path workspace, String baselineSha, PlannedDependencyChange change,
            String[] coordinates, RepositoryPomIndex finalIndex, String owningPath) {
        EffectiveVersion finalVersion = resolveEffectivePlannedVersion(owningPath, finalIndex, coordinates);
        if (finalVersion.deferToPhaseB()) {
            return VersionCheckResult.pending();
        }
        if (finalVersion.value() == null) {
            return VersionCheckResult.violation("no dependencyManagement or BOM entry found anywhere "
                    + "applicable to " + owningPath + " that could affect the version of "
                    + change.dependencyCoordinates());
        }
        if (!finalVersion.value().equals(change.targetVersion())) {
            return VersionCheckResult.violation(change.dependencyCoordinates() + " resolves to "
                    + finalVersion.value() + " but the approved plan specified target version "
                    + change.targetVersion());
        }

        // A resolved match against the target is only a genuine remediation if it is actually new --
        // re-run the same scoped resolution against the baseline to rule out a no-op attempt that
        // happened to land on a repository already at the planned target.
        RepositoryPomIndex baselineIndex = new RepositoryPomIndex(new BaselinePomSource(git, workspace, baselineSha));
        EffectiveVersion baselineVersion = resolveEffectivePlannedVersion(owningPath, baselineIndex, coordinates);
        if (change.targetVersion().equals(baselineVersion.value())) {
            return VersionCheckResult.violation("planned target version " + change.targetVersion() + " for "
                    + change.dependencyCoordinates() + " was already present at the baseline; this attempt "
                    + "made no relevant change");
        }
        return VersionCheckResult.conforms();
    }

    /**
     * The management-only path: no direct {@code <dependency>} exists anywhere for these coordinates, so
     * the entry {@code declaringPath} owns is what the plan's {@code VERSION_BUMP} must actually be
     * bumping -- an existing {@code dependencyManagement} entry or imported BOM. {@code VERSION_BUMP}
     * requires that entry to have already existed at the baseline: one appearing only in the final state
     * is a new entry, which is {@code DEPENDENCY_MANAGEMENT_ADDITION}'s shape, not this one's, and is
     * fail-closed here rather than silently accepted as if it were the same thing.
     */
    private static VersionCheckResult checkVersionBumpAgainstManagedEntry(
            GitCommandRunner git, Path workspace, String baselineSha, PlannedDependencyChange change,
            String[] coordinates, RepositoryPomIndex finalIndex, String declaringPath) {
        RepositoryPomIndex baselineIndex = new RepositoryPomIndex(new BaselinePomSource(git, workspace, baselineSha));
        if (findApplicableDependencyManagement(declaringPath, baselineIndex, coordinates) == null) {
            return VersionCheckResult.violation("planned changeType is VERSION_BUMP for "
                    + change.dependencyCoordinates() + ", but no dependencyManagement/BOM entry for it existed "
                    + "at the baseline in " + declaringPath + " -- an entry that did not exist before this "
                    + "attempt is a new dependencyManagement entry (DEPENDENCY_MANAGEMENT_ADDITION), not a "
                    + "version bump of an existing one");
        }

        EffectiveVersion finalVersion = resolveEffectiveManagedVersion(declaringPath, finalIndex, coordinates);
        if (finalVersion.deferToPhaseB()) {
            return VersionCheckResult.pending();
        }
        if (finalVersion.value() == null) {
            return VersionCheckResult.violation("the dependencyManagement/BOM entry for "
                    + change.dependencyCoordinates() + " in " + declaringPath + " does not resolve to a "
                    + "version this repository's own POM files can prove");
        }
        if (!finalVersion.value().equals(change.targetVersion())) {
            return VersionCheckResult.violation(change.dependencyCoordinates() + " resolves to "
                    + finalVersion.value() + " but the approved plan specified target version "
                    + change.targetVersion());
        }

        EffectiveVersion baselineVersion = resolveEffectiveManagedVersion(declaringPath, baselineIndex, coordinates);
        if (change.targetVersion().equals(baselineVersion.value())) {
            return VersionCheckResult.violation("planned target version " + change.targetVersion() + " for "
                    + change.dependencyCoordinates() + " was already present at the baseline; this attempt "
                    + "made no relevant change");
        }
        return VersionCheckResult.conforms();
    }

    // ---- DEPENDENCY_MANAGEMENT_ADDITION -------------------------------------------------------------

    private static String discoverManagementEntry(
            List<String> pomFiles, RepositoryPomIndex index, String[] coordinates) {
        for (String path : pomFiles) {
            Document doc = index.documentAt(path);
            if (doc == null) {
                continue;
            }
            if (findDependencyElement(doc, coordinates[0], coordinates[1], true) != null) {
                return path;
            }
        }
        return null;
    }

    /** {@code null} when conformant (and, if resolved, a genuine change from baseline); otherwise the
     *  specific reason it is not. */
    private static String dependencyManagementViolation(
            GitCommandRunner git, Path workspace, String baselineSha, List<String> pomFiles,
            PlannedDependencyChange change) {
        String[] coordinates = splitCoordinates(change.dependencyCoordinates());
        RepositoryPomIndex finalIndex = new RepositoryPomIndex(new FilesystemPomSource(workspace));
        String declaringPath = discoverManagementEntry(pomFiles, finalIndex, coordinates);
        if (declaringPath == null) {
            return "planned dependencyManagement entry for " + change.dependencyCoordinates() + "="
                    + change.targetVersion() + " was not found in any of this repository's POM files";
        }

        EffectiveVersion finalVersion = resolveEffectiveManagedVersion(declaringPath, finalIndex, coordinates);
        if (!change.targetVersion().equals(finalVersion.value())) {
            return "planned dependencyManagement entry for " + change.dependencyCoordinates() + " resolves "
                    + "to " + (finalVersion.value() == null ? "an unresolvable value" : finalVersion.value())
                    + ", not the planned target " + change.targetVersion();
        }

        RepositoryPomIndex baselineIndex = new RepositoryPomIndex(new BaselinePomSource(git, workspace, baselineSha));
        EffectiveVersion baselineVersion = resolveEffectiveManagedVersion(declaringPath, baselineIndex, coordinates);
        if (change.targetVersion().equals(baselineVersion.value())) {
            return "planned dependencyManagement entry for " + change.dependencyCoordinates() + "="
                    + change.targetVersion() + " was already present at the baseline; this attempt made no "
                    + "relevant change";
        }
        return null;
    }

    // ---- EXCLUSION_ADDED ----------------------------------------------------------------------------

    /**
     * {@code null} when every one of {@code change}'s {@code excludedCoordinates} is nested under its own
     * {@code dependencyCoordinates} host somewhere in this repository's POM files; otherwise names exactly
     * which of them are not. Fixes run {@code 20260920-052841-210614}: an excluded coordinate present
     * SOMEWHERE in the repository, but nested under a different dependency than the plan's own named host,
     * is never enough -- {@code EXCLUSION_ADDED} is a claim about one specific host's own
     * {@code <exclusions>} block, not "this artifact is excluded from something."
     */
    private static String exclusionViolation(Path workspace, List<String> pomFiles, PlannedDependencyChange change) {
        String[] hostCoordinates = splitCoordinates(change.dependencyCoordinates());
        List<String> missing = new ArrayList<>();
        for (String excludedCoordinate : change.excludedCoordinates()) {
            if (!hasExclusionUnderHost(workspace, pomFiles, hostCoordinates, splitCoordinates(excludedCoordinate))) {
                missing.add(excludedCoordinate);
            }
        }
        if (missing.isEmpty()) {
            return null;
        }
        return "planned exclusion(s) " + String.join(", ", missing) + " were not found nested under "
                + change.dependencyCoordinates() + "'s own <dependency> element in any of this "
                + "repository's POM files";
    }

    /** Whether {@code excludedCoordinates} appears as an {@code <exclusion>} nested anywhere inside a
     *  {@code <dependency>} element matching {@code hostCoordinates} -- never merely present somewhere
     *  else in the same POM. */
    private static boolean hasExclusionUnderHost(
            Path workspace, List<String> pomFiles, String[] hostCoordinates, String[] excludedCoordinates) {
        for (String file : pomFiles) {
            Document doc = parseXml(workspace.resolve(file));
            if (doc == null) {
                continue;
            }
            NodeList dependencies = doc.getElementsByTagName("dependency");
            for (int i = 0; i < dependencies.getLength(); i++) {
                Element dependency = (Element) dependencies.item(i);
                if (!hostCoordinates[0].equals(childText(dependency, "groupId"))
                        || !hostCoordinates[1].equals(childText(dependency, "artifactId"))) {
                    continue;
                }
                NodeList exclusions = dependency.getElementsByTagName("exclusion");
                for (int j = 0; j < exclusions.getLength(); j++) {
                    Element exclusion = (Element) exclusions.item(j);
                    if (excludedCoordinates[0].equals(childText(exclusion, "groupId"))
                            && excludedCoordinates[1].equals(childText(exclusion, "artifactId"))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // ---- XML plumbing ---------------------------------------------------------------------------------

    private static Document parseXml(Path file) {
        try {
            return parseXmlFromString(Files.readString(file, StandardCharsets.UTF_8));
        } catch (IOException e) {
            return null;
        }
    }

    private static Document parseXmlFromString(String content) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(false);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
        } catch (IOException | ParserConfigurationException | SAXException | RuntimeException e) {
            return null;
        }
    }

    private static Element findDependencyElement(
            Document doc, String groupId, String artifactId, boolean mustBeUnderDependencyManagement) {
        NodeList dependencies = doc.getElementsByTagName("dependency");
        for (int i = 0; i < dependencies.getLength(); i++) {
            Element dependency = (Element) dependencies.item(i);
            if (!groupId.equals(childText(dependency, "groupId"))
                    || !artifactId.equals(childText(dependency, "artifactId"))) {
                continue;
            }
            if (hasAncestorNamed(dependency, "dependencyManagement") == mustBeUnderDependencyManagement) {
                return dependency;
            }
        }
        return null;
    }

    private static boolean hasAncestorNamed(Element element, String tagName) {
        Node parent = element.getParentNode();
        while (parent != null) {
            if (parent instanceof Element parentElement && tagName.equals(parentElement.getTagName())) {
                return true;
            }
            parent = parent.getParentNode();
        }
        return false;
    }

    private static Element directChildElement(Element parent, String tagName) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            if (children.item(i) instanceof Element element && tagName.equals(element.getTagName())) {
                return element;
            }
        }
        return null;
    }

    private static String childText(Element parent, String tagName) {
        Element child = directChildElement(parent, tagName);
        if (child == null) {
            return null;
        }
        String text = child.getTextContent();
        return text == null ? null : text.strip();
    }

    private static String[] splitCoordinates(String coordinates) {
        int separator = coordinates.indexOf(':');
        return separator < 0
                ? new String[] {coordinates, ""}
                : new String[] {coordinates.substring(0, separator), coordinates.substring(separator + 1)};
    }
}
