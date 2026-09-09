package com.tungsten.depbot.report.actionable;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.RecordComponent;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ActionableModelTest {

    private static final String ACTIONABLE_PACKAGE = "com.tungsten.depbot.report.actionable";

    private static final List<Class<?>> MODEL_CLASSES = List.of(
            ActionableReport.class,
            ActionableSummary.class,
            ActionableFinding.class,
            AffectedLibrary.class,
            FindingLocation.class,
            Remediation.class,
            RecommendedFix.class);

    private static ActionableSummary summary() {
        return new ActionableSummary(7, 1, 3, 2, 1, 0, 4);
    }

    private static ActionableFinding finding(String id) {
        return new ActionableFinding(id, "SECURITY_VULNERABILITY", "HIGH", "high", "8.1", 8.1,
                "8.1", "FAKE/AV:N", "synthetic description", "2020-01-01", "2020-02-02",
                "https://example.invalid/a", "synthetic-product", "synthetic-project",
                null, null, null);
    }

    // ---------- report version ----------

    @Test
    @DisplayName("the factory stamps the current schema version")
    void factoryStampsVersion() {
        ActionableReport report = ActionableReport.of("2026-01-02T03:04:05Z", summary(), List.of());

        assertEquals("1.1", report.reportVersion());
        assertEquals("1.1", ActionableReport.CURRENT_VERSION);
    }

    @Test
    @DisplayName("a null or blank version falls back to the current version")
    void blankVersionFallsBack() {
        assertEquals("1.1",
                new ActionableReport("t", null, summary(), List.of()).reportVersion());
        assertEquals("1.1",
                new ActionableReport("t", "   ", summary(), List.of()).reportVersion());
    }

    // ---------- collections are never null ----------

    @Test
    @DisplayName("null findings become an empty list")
    void nullFindingsBecomeEmpty() {
        ActionableReport report = new ActionableReport("t", "1.1", summary(), null);

        assertNotNull(report.findings());
        assertTrue(report.findings().isEmpty());
        assertFalse(report.hasActionableFindings());
    }

    @Test
    @DisplayName("null locations become an empty list")
    void nullLocationsBecomeEmpty() {
        assertNotNull(finding("FAKE-CVE-0000-0001").locations());
        assertTrue(finding("FAKE-CVE-0000-0001").locations().isEmpty());
    }

    @Test
    @DisplayName("null allFixes become an empty list")
    void nullAllFixesBecomeEmpty() {
        Remediation remediation = new Remediation(null, null);

        assertNotNull(remediation.allFixes());
        assertTrue(remediation.allFixes().isEmpty());
    }

    @Test
    @DisplayName("a null remediation becomes the empty remediation")
    void nullRemediationBecomesEmpty() {
        ActionableFinding f = finding("FAKE-CVE-0000-0002");

        assertNotNull(f.remediation());
        assertNull(f.remediation().topFix());
        assertTrue(f.remediation().allFixes().isEmpty());
        assertFalse(f.remediation().hasAnyFix());
        assertFalse(f.remediation().hasTopFix());
    }

    // ---------- collections are immutable defensive copies ----------

    @Test
    @DisplayName("findings cannot be modified through the accessor")
    void findingsAreImmutable() {
        ActionableReport report = ActionableReport.of("t", summary(),
                List.of(finding("FAKE-CVE-0000-0003")));

        assertThrows(UnsupportedOperationException.class,
                () -> report.findings().add(finding("FAKE-CVE-0000-0004")));
    }

    @Test
    @DisplayName("mutating the source list afterwards does not change the report")
    void findingsAreDefensivelyCopied() {
        List<ActionableFinding> source = new ArrayList<>();
        source.add(finding("FAKE-CVE-0000-0005"));

        ActionableReport report = ActionableReport.of("t", summary(), source);
        source.add(finding("FAKE-CVE-0000-0006"));
        source.clear();

        assertEquals(1, report.findings().size(), "the report kept a reference to a live list");
        assertEquals("FAKE-CVE-0000-0005", report.findings().get(0).vulnerabilityId());
    }

    @Test
    @DisplayName("locations are immutable and defensively copied")
    void locationsAreImmutableAndCopied() {
        List<FindingLocation> source = new ArrayList<>();
        source.add(new FindingLocation("/synthetic/a.jar", "EXACT_MATCH"));

        ActionableFinding f = new ActionableFinding("id", null, "HIGH", null, null, null, null,
                null, null, null, null, null, null, null, null, source, null);
        source.clear();

        assertEquals(1, f.locations().size());
        assertThrows(UnsupportedOperationException.class,
                () -> f.locations().add(new FindingLocation("/synthetic/b.jar", "FILENAME_MATCH")));
    }

    @Test
    @DisplayName("allFixes are immutable and defensively copied")
    void allFixesAreImmutableAndCopied() {
        List<RecommendedFix> source = new ArrayList<>();
        source.add(new RecommendedFix(null, "UPGRADE_VERSION", null, null,
                "com.example.fake:example-fake-lib:1.0.1", null, null));

        Remediation remediation = new Remediation(null, source);
        source.clear();

        assertEquals(1, remediation.allFixes().size());
        assertThrows(UnsupportedOperationException.class,
                () -> remediation.allFixes().add(new RecommendedFix(null, "PATCH", null, null,
                        null, null, null)));
    }

    @Test
    @DisplayName("null collection elements are rejected rather than silently filtered")
    void nullElementsAreRejected() {
        // Removing nulls is the mapper's job. A null reaching a model indicates an upstream
        // defect, so it should surface here instead of being quietly absorbed.
        List<FindingLocation> withNull = new ArrayList<>();
        withNull.add(null);

        assertThrows(NullPointerException.class,
                () -> new ActionableFinding("id", null, "HIGH", null, null, null, null, null,
                        null, null, null, null, null, null, null, withNull, null));
    }

    // ---------- nullable optional nested objects ----------

    @Test
    @DisplayName("an absent library and topFix remain null")
    void optionalNestedObjectsMayBeNull() {
        ActionableFinding f = finding("FAKE-CVE-0000-0007");

        assertNull(f.library());
        assertNull(f.remediation().topFix());
    }

    @Test
    @DisplayName("Remediation.empty() carries no recommendation")
    void emptyRemediation() {
        assertNull(Remediation.empty().topFix());
        assertTrue(Remediation.empty().allFixes().isEmpty());
        assertFalse(Remediation.empty().hasAnyFix());
    }

    // ---------- summary ----------

    @Test
    @DisplayName("summary exposes the bucket sum for invariant checks")
    void summaryBucketSum() {
        assertEquals(7, summary().sumOfBuckets());
        assertEquals(summary().totalVulnerabilities(), summary().sumOfBuckets());
        assertEquals(4, summary().actionableCount());
    }

    // ---------- architectural boundary ----------

    @Test
    @DisplayName("report models never reference Mend integration models")
    void reportModelsAreIndependentOfMendModels() {
        List<String> violations = new ArrayList<>();

        for (Class<?> modelClass : MODEL_CLASSES) {
            assertTrue(modelClass.isRecord(), modelClass.getSimpleName() + " should be a record");

            for (RecordComponent component : modelClass.getRecordComponents()) {
                Class<?> type = component.getType();
                String packageName = type.isPrimitive() || type.getPackage() == null
                        ? "java.lang"
                        : type.getPackage().getName();

                boolean permitted = packageName.startsWith("java.")
                        || packageName.equals(ACTIONABLE_PACKAGE);

                if (!permitted) {
                    violations.add(modelClass.getSimpleName() + "." + component.getName()
                            + " is of type " + type.getName());
                }
            }
        }

        assertTrue(violations.isEmpty(),
                "Report output models must stay independent of the Mend integration models so a "
                        + "vendor API change cannot reshape the published contract. Violations: "
                        + violations);
    }

    @Test
    @DisplayName("the guard would actually catch a foreign type")
    void boundaryGuardIsNotVacuous() {
        // Proves the check above inspects something: every model has components, and at least one
        // carries a type from the actionable package rather than only java.* scalars.
        int componentCount = 0;
        boolean sawActionableType = false;

        for (Class<?> modelClass : MODEL_CLASSES) {
            for (RecordComponent component : modelClass.getRecordComponents()) {
                componentCount++;
                Class<?> type = component.getType();
                if (type.getPackage() != null
                        && ACTIONABLE_PACKAGE.equals(type.getPackage().getName())) {
                    sawActionableType = true;
                }
            }
        }

        assertTrue(componentCount > 40, "expected to inspect many components, saw " + componentCount);
        assertTrue(sawActionableType, "guard never encountered an actionable-package type");
    }
}
