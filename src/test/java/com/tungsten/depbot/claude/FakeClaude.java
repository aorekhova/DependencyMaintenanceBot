package com.tungsten.depbot.claude;

import com.tungsten.depbot.assessment.BatchAnalysisFinalizationPromptRenderer;
import com.tungsten.depbot.humanreview.HumanReviewFinalizationPromptRenderer;
import com.tungsten.depbot.implementation.ImplementationFinalizationPromptRenderer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A stand-in for the Claude Code executable, so tests exercise the real {@link ProcessBuilder} path
 * -- argument passing, the working directory, stdin, stdout, stderr, exit codes and timeouts --
 * without ever starting the real agent or touching a real product repository.
 *
 * <p>Each fake records what it was given into its own recording directory, which is what lets a
 * test assert on the exact arguments and prompt Claude would have received.
 *
 * <p><strong>One fake serves both phases.</strong> {@link Builder#respondingTo} scripts a different
 * answer for {@link ClaudePhase#ASSESSMENT} and {@link ClaudePhase#IMPLEMENTATION}, which is what
 * makes a two-call remediation testable end to end against a single executable -- the same shape the
 * production wiring has, where one invoker serves both services. The phase is detected from
 * {@link ClaudePhase#promptMarker()} in the prompt the fake receives on standard input, so what
 * decides the answer is the document actually delivered to the process, not a call counter that would
 * pass whether or not the right prompt arrived.
 *
 * <p>A prompt carrying no marker gets the unscripted default response, so a fake built without any
 * phase-specific answer behaves exactly as it did before phases existed.
 */
public final class FakeClaude {

    private static final boolean WINDOWS =
            System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win");

    /** Recorded for a prompt that declared no phase. */
    private static final String NO_PHASE = "none";

    /**
     * One kind of finalization call this fake can recognise and answer separately from the ordinary
     * phase responses: a short {@code goto} key for the generated script, the searchable part of that
     * kind's own marker (without the HTML comment punctuation -- {@code findstr /c:} and {@code grep}
     * both take it as a literal, and {@code <}/{@code >} would be redirection operators in both shells
     * if they were included), and the label recorded in the phase sequence.
     */
    private record FinalizationKind(String key, String markerBody, String sequenceLabel) {
    }

    private static final FinalizationKind ASSESSMENT_FINALIZATION = new FinalizationKind(
            "assessment", "depbot-finalization:ASSESSMENT", "assessment-finalization");
    private static final FinalizationKind IMPLEMENTATION_FINALIZATION = new FinalizationKind(
            "implementation", "depbot-finalization:IMPLEMENTATION", "implementation-finalization");
    private static final FinalizationKind HUMAN_REVIEW_FINALIZATION = new FinalizationKind(
            "humanreview", "depbot-finalization:HUMAN_REVIEW", "human-review-finalization");
    private static final FinalizationKind ASSESSMENT_SECOND_ATTEMPT = new FinalizationKind(
            "assessmentsecondattempt", "depbot-second-attempt:ASSESSMENT", "assessment-second-attempt");
    private static final FinalizationKind ASSESSMENT_SCHEMA_REPAIR = new FinalizationKind(
            "assessmentschemarepair", "depbot-schema-repair:ASSESSMENT", "assessment-schema-repair");
    private static final List<FinalizationKind> FINALIZATION_KINDS = List.of(
            ASSESSMENT_FINALIZATION, IMPLEMENTATION_FINALIZATION, HUMAN_REVIEW_FINALIZATION,
            ASSESSMENT_SECOND_ATTEMPT, ASSESSMENT_SCHEMA_REPAIR);

    private final Path executable;
    private final Path recordingDirectory;

    private FakeClaude(Path executable, Path recordingDirectory) {
        this.executable = executable;
        this.recordingDirectory = recordingDirectory;
    }

    public Path executable() {
        return executable;
    }

    /** The arguments the fake was invoked with, as one line. Empty when it was never invoked. */
    public String recordedArgs() throws IOException {
        return read("args.txt");
    }

    /** The prompt the fake received on standard input. */
    public String recordedStdin() throws IOException {
        return read("stdin.txt");
    }

    /** The working directory the fake ran in. */
    public String recordedWorkingDirectory() throws IOException {
        return read("cwd.txt").strip();
    }

    /** A copy of the snapshot file, taken while the fake was running. */
    public String recordedSnapshot() throws IOException {
        return read("snapshot.txt");
    }

    /** How many times this fake was invoked, counted by appended marker lines. */
    public int invocationCount() throws IOException {
        String marker = read("invocations.txt");
        return marker.isBlank() ? 0 : (int) marker.lines().filter(line -> !line.isBlank()).count();
    }

    /**
     * The branch checked out in this fake's working directory at the start of each invocation, in
     * invocation order -- one line per call, always recorded regardless of builder options. This is
     * what proves severities were processed strictly one at a time on the branch they were supposed
     * to be on, rather than merely inferring order from log lines.
     */
    public List<String> recordedBranchSequence() throws IOException {
        return lines("branch-sequence.txt");
    }

    /**
     * The phase each invocation's prompt declared, in invocation order: {@code "assessment"},
     * {@code "implementation"}, or {@code "none"} for a prompt with no marker. Proves both that the
     * two calls happened and that they happened in the right order.
     */
    public List<String> recordedPhaseSequence() throws IOException {
        return lines("phase-sequence.txt");
    }

    private List<String> lines(String name) throws IOException {
        List<String> lines = new ArrayList<>();
        for (String line : read(name).lines().toList()) {
            if (!line.isBlank()) {
                lines.add(line.strip());
            }
        }
        return lines;
    }

    private String read(String name) throws IOException {
        Path path = recordingDirectory.resolve(name);
        return Files.exists(path) ? Files.readString(path, StandardCharsets.UTF_8) : "";
    }

    public static Builder in(Path directory) {
        return new Builder(directory);
    }

    /** Configures one fake. Defaults to a clean, immediate, successful run. */
    public static final class Builder {

        private final Path directory;
        private String name = "fake-claude";
        private int exitCode = 0;
        private String stdout = "{\"result\":\"ok\"}";
        private String stderr = "";
        private int sleepSeconds = 0;
        private Path snapshotSource;
        private final Map<String, String> filesToCreate = new LinkedHashMap<>();
        private final List<String> filesToDelete = new ArrayList<>();
        private final Map<ClaudePhase, PhaseResponse> phaseResponses = new EnumMap<>(ClaudePhase.class);
        private final Map<ClaudePhase, Map<String, String>> phaseFilesToCreate =
                new EnumMap<>(ClaudePhase.class);
        private final Map<Integer, Map<String, String>> invocationFilesToCreate = new LinkedHashMap<>();
        private final Map<ClaudePhase, List<String>> phaseGitCommands = new EnumMap<>(ClaudePhase.class);
        private final Map<FinalizationKind, PhaseResponse> finalizationResponses = new LinkedHashMap<>();

        private Builder(Path directory) {
            this.directory = directory;
        }

        public Builder named(String value) {
            this.name = value;
            return this;
        }

        public Builder exitingWith(int value) {
            this.exitCode = value;
            return this;
        }

        public Builder printing(String value) {
            this.stdout = value;
            return this;
        }

        public Builder printingToStderr(String value) {
            this.stderr = value;
            return this;
        }

        /**
         * Answers a prompt declaring {@code phase} with {@code stdout} and exit code 0, leaving every
         * other phase on whatever {@link #printing} and {@link #exitingWith} set.
         */
        public Builder respondingTo(ClaudePhase phase, String stdout) {
            return respondingTo(phase, stdout, 0);
        }

        /** Answers a prompt declaring {@code phase} with {@code stdout} and {@code exitCode}. */
        public Builder respondingTo(ClaudePhase phase, String stdout, int exitCode) {
            phaseResponses.put(phase, new PhaseResponse(stdout, exitCode));
            return this;
        }

        /**
         * Answers the batch analysis finalization call -- the short, tool-free call the orchestrator
         * makes on its own, after a prompt carrying
         * {@link BatchAnalysisFinalizationPromptRenderer#FINALIZATION_MARKER} -- with {@code stdout} and
         * exit code 0. Detected ahead of every {@link #respondingTo phase response}, since a finalization
         * prompt is never mistaken for an ordinary assessment prompt.
         */
        public Builder respondingToAssessmentFinalization(String stdout) {
            return respondingToAssessmentFinalization(stdout, 0);
        }

        /** Answers the assessment finalization call with {@code stdout} and {@code exitCode}. */
        public Builder respondingToAssessmentFinalization(String stdout, int exitCode) {
            finalizationResponses.put(ASSESSMENT_FINALIZATION, new PhaseResponse(stdout, exitCode));
            return this;
        }

        /**
         * Answers the second Vulnerability Analysis attempt -- the full-tools call the orchestrator makes
         * on its own after the first attempt ran out of turns or time, after a prompt carrying
         * {@link BatchAnalysisSecondAttemptPromptRenderer#SECOND_ATTEMPT_MARKER} -- with {@code stdout}
         * and exit code 0.
         */
        public Builder respondingToAssessmentSecondAttempt(String stdout) {
            return respondingToAssessmentSecondAttempt(stdout, 0);
        }

        /** Answers the second Vulnerability Analysis attempt with {@code stdout} and {@code exitCode}. */
        public Builder respondingToAssessmentSecondAttempt(String stdout, int exitCode) {
            finalizationResponses.put(ASSESSMENT_SECOND_ATTEMPT, new PhaseResponse(stdout, exitCode));
            return this;
        }

        /**
         * Answers the one bounded schema-repair call -- the short, tool-free call the orchestrator makes
         * on its own after a whole-batch analysis completed substantively but its document could not be
         * parsed or validated, after a prompt carrying
         * {@link com.tungsten.depbot.assessment.BatchAnalysisSchemaRepairPromptRenderer#SCHEMA_REPAIR_MARKER}
         * -- with {@code stdout} and exit code 0.
         */
        public Builder respondingToAssessmentSchemaRepair(String stdout) {
            return respondingToAssessmentSchemaRepair(stdout, 0);
        }

        /** Answers the schema-repair call with {@code stdout} and {@code exitCode}. */
        public Builder respondingToAssessmentSchemaRepair(String stdout, int exitCode) {
            finalizationResponses.put(ASSESSMENT_SCHEMA_REPAIR, new PhaseResponse(stdout, exitCode));
            return this;
        }

        /**
         * Answers the implementation finalization call -- the short, read-only call the orchestrator
         * makes on its own, after a prompt carrying
         * {@link ImplementationFinalizationPromptRenderer#FINALIZATION_MARKER} -- with {@code stdout}
         * and exit code 0.
         */
        public Builder respondingToImplementationFinalization(String stdout) {
            return respondingToImplementationFinalization(stdout, 0);
        }

        /** Answers the implementation finalization call with {@code stdout} and {@code exitCode}. */
        public Builder respondingToImplementationFinalization(String stdout, int exitCode) {
            finalizationResponses.put(IMPLEMENTATION_FINALIZATION, new PhaseResponse(stdout, exitCode));
            return this;
        }

        /**
         * Answers the Human Review finalization call -- the short, tool-free call the orchestrator
         * makes on its own, after a prompt carrying
         * {@link HumanReviewFinalizationPromptRenderer#FINALIZATION_MARKER} -- with {@code stdout} and
         * exit code 0.
         */
        public Builder respondingToHumanReviewFinalization(String stdout) {
            return respondingToHumanReviewFinalization(stdout, 0);
        }

        /** Answers the Human Review finalization call with {@code stdout} and {@code exitCode}. */
        public Builder respondingToHumanReviewFinalization(String stdout, int exitCode) {
            finalizationResponses.put(HUMAN_REVIEW_FINALIZATION, new PhaseResponse(stdout, exitCode));
            return this;
        }

        /**
         * Creates a file <em>only</em> on a call whose prompt declares {@code phase}.
         *
         * <p>Necessary as soon as a test drives both phases through one fake: an unconditional
         * {@link #creatingFile} would have the assessment call editing the workspace too, which is the
         * one thing a read-only phase must never do -- and it would leave the tree dirty before the
         * remediation branch even exists.
         */
        public Builder creatingFile(ClaudePhase phase, String relativePath, String content) {
            phaseFilesToCreate.computeIfAbsent(phase, ignored -> new LinkedHashMap<>())
                    .put(relativePath, content);
            return this;
        }

        /**
         * Runs {@code git <commandLine>} as a side effect of a call whose prompt declares {@code phase},
         * before the canned response is printed -- simulates Claude using its own local git access
         * (switching branches, committing, or anything else) mid-session, now that it has one. May be
         * called more than once per phase; commands run in the order they were added.
         *
         * <p>{@code commandLine} is embedded in the generated script as a single, unquoted token list,
         * so it must not itself need shell quoting -- keep commit messages and the like free of spaces
         * requiring quotes (an underscore instead of a space is enough for a test fixture).
         */
        public Builder runningGitCommand(ClaudePhase phase, String commandLine) {
            phaseGitCommands.computeIfAbsent(phase, ignored -> new ArrayList<>()).add(commandLine);
            return this;
        }

        /** Makes the fake outlast a shorter timeout, so the kill path can be exercised. */
        public Builder sleepingFor(int seconds) {
            this.sleepSeconds = seconds;
            return this;
        }

        /** Copies this file while the fake is running, capturing mid-run state such as the manifest. */
        public Builder snapshotting(Path source) {
            this.snapshotSource = source;
            return this;
        }

        /**
         * Creates or overwrites a file at {@code relativePath}, resolved against the fake's actual
         * working directory at invocation time (not the recordings folder) -- this is what stands
         * in for "Claude edited a file" in tests that need something for the orchestrator's
         * commit/rollback logic to actually find.
         */
        public Builder creatingFile(String relativePath, String content) {
            filesToCreate.put(relativePath, content);
            return this;
        }

        /**
         * Deletes a file at {@code relativePath} in the fake's working directory at invocation
         * time -- used to simulate a unit that removes something it should not (e.g. a test file).
         */
        public Builder deletingFile(String relativePath) {
            filesToDelete.add(relativePath);
            return this;
        }

        /**
         * Creates or overwrites a file at {@code relativePath} only on the {@code invocationNumber}-th
         * call to this fake overall (1-based, counting every phase together, the same numbering
         * {@link #invocationCount()} reports).
         *
         * <p>Necessary as soon as a test drives two sequential calls to the <em>same</em> phase that
         * must each leave a genuinely different diff -- for instance two independent remediation groups
         * committing, one after another, onto the one shared branch a run's cohort now uses.
         * {@link #creatingFile(ClaudePhase, String, String)} cannot do this: it writes the same static
         * content on every call of that phase, which is a no-op diff on the second call once the first
         * has already left that exact content in place.
         */
        public Builder creatingFileOnInvocation(int invocationNumber, String relativePath, String content) {
            invocationFilesToCreate.computeIfAbsent(invocationNumber, ignored -> new LinkedHashMap<>())
                    .put(relativePath, content);
            return this;
        }

        public FakeClaude build() throws IOException {
            Path recordings = directory.resolve(name + "-recordings");
            Files.createDirectories(recordings);
            Path canned = recordings.resolve("canned-stdout.txt");
            Path cannedError = recordings.resolve("canned-stderr.txt");
            Files.writeString(canned, stdout, StandardCharsets.UTF_8);
            Files.writeString(cannedError, stderr, StandardCharsets.UTF_8);

            Map<ClaudePhase, Path> phaseStdout = new EnumMap<>(ClaudePhase.class);
            for (Map.Entry<ClaudePhase, PhaseResponse> entry : phaseResponses.entrySet()) {
                Path source = recordings.resolve("canned-" + entry.getKey().directoryName() + ".txt");
                Files.writeString(source, entry.getValue().stdout(), StandardCharsets.UTF_8);
                phaseStdout.put(entry.getKey(), source);
            }

            Map<FinalizationKind, Path> finalizationStdouts = new LinkedHashMap<>();
            for (Map.Entry<FinalizationKind, PhaseResponse> entry : finalizationResponses.entrySet()) {
                Path source = recordings.resolve("canned-" + entry.getKey().sequenceLabel() + ".txt");
                Files.writeString(source, entry.getValue().stdout(), StandardCharsets.UTF_8);
                finalizationStdouts.put(entry.getKey(), source);
            }

            Map<String, Path> createSources = new LinkedHashMap<>();
            int index = 0;
            for (Map.Entry<String, String> entry : filesToCreate.entrySet()) {
                Path source = recordings.resolve("creating-" + index + ".txt");
                Files.writeString(source, entry.getValue(), StandardCharsets.UTF_8);
                createSources.put(entry.getKey(), source);
                index++;
            }

            Map<ClaudePhase, Map<String, Path>> phaseCreateSources = new EnumMap<>(ClaudePhase.class);
            for (Map.Entry<ClaudePhase, Map<String, String>> phaseEntry : phaseFilesToCreate.entrySet()) {
                Map<String, Path> sources = new LinkedHashMap<>();
                int phaseIndex = 0;
                for (Map.Entry<String, String> entry : phaseEntry.getValue().entrySet()) {
                    Path source = recordings.resolve(
                            "creating-" + phaseEntry.getKey().directoryName() + "-" + phaseIndex + ".txt");
                    Files.writeString(source, entry.getValue(), StandardCharsets.UTF_8);
                    sources.put(entry.getKey(), source);
                    phaseIndex++;
                }
                phaseCreateSources.put(phaseEntry.getKey(), sources);
            }

            Map<Integer, Map<String, Path>> invocationCreateSources = new LinkedHashMap<>();
            for (Map.Entry<Integer, Map<String, String>> invocationEntry : invocationFilesToCreate.entrySet()) {
                Map<String, Path> sources = new LinkedHashMap<>();
                int invocationIndex = 0;
                for (Map.Entry<String, String> entry : invocationEntry.getValue().entrySet()) {
                    Path source = recordings.resolve(
                            "creating-invocation-" + invocationEntry.getKey() + "-" + invocationIndex + ".txt");
                    Files.writeString(source, entry.getValue(), StandardCharsets.UTF_8);
                    sources.put(entry.getKey(), source);
                    invocationIndex++;
                }
                invocationCreateSources.put(invocationEntry.getKey(), sources);
            }

            Path script = directory.resolve(WINDOWS ? name + ".cmd" : name + ".sh");
            Files.writeString(script,
                    WINDOWS
                            ? windowsScript(recordings, canned, cannedError, createSources, phaseStdout,
                                    phaseCreateSources, finalizationStdouts, invocationCreateSources)
                            : posixScript(recordings, canned, cannedError, createSources, phaseStdout,
                                    phaseCreateSources, finalizationStdouts, invocationCreateSources),
                    StandardCharsets.UTF_8);
            if (!WINDOWS) {
                script.toFile().setExecutable(true);
            }
            return new FakeClaude(script, recordings);
        }

        private String windowsScript(
                Path recordings, Path canned, Path cannedError,
                Map<String, Path> createSources, Map<ClaudePhase, Path> phaseStdout,
                Map<ClaudePhase, Map<String, Path>> phaseCreateSources,
                Map<FinalizationKind, Path> finalizationStdouts,
                Map<Integer, Map<String, Path>> invocationCreateSources) {

            StringBuilder script = new StringBuilder();
            script.append("@echo off\r\n");
            Path invocations = recordings.resolve("invocations.txt");
            script.append("echo invoked>> \"").append(invocations).append("\"\r\n");
            script.append("echo %* > \"").append(recordings.resolve("args.txt")).append("\"\r\n");
            script.append("cd > \"").append(recordings.resolve("cwd.txt")).append("\"\r\n");
            script.append("git rev-parse --abbrev-ref HEAD >> \"")
                    .append(recordings.resolve("branch-sequence.txt")).append("\" 2>nul\r\n");
            if (!invocationCreateSources.isEmpty()) {
                // Marker files, not a piped line count: a `for /f` reading through `find` under a
                // ProcessBuilder with no console has hung outright in this environment (a Windows/OneDrive
                // checkout with no attached console is exactly where such things go wrong). Counting is
                // done in two steps, both by marker existence alone, with nothing piped or subshelled:
                // first, which call (1st, 2nd, ...) this is overall -- one marker consumed per call, in
                // order, regardless of phase, so a read-only call still advances the count; then, which
                // configured file set (if any) belongs to that exact call number.
                int maxOrdinal = java.util.Collections.max(invocationCreateSources.keySet());
                for (int callNumber = 1; callNumber <= maxOrdinal; callNumber++) {
                    Path countMarker = recordings.resolve("invocation-count-" + callNumber + ".marker");
                    script.append("if not exist \"").append(countMarker).append("\" (\r\n");
                    script.append("  echo done > \"").append(countMarker).append("\"\r\n");
                    script.append("  set DEPBOT_INVOCATION_COUNT=").append(callNumber).append("\r\n");
                    script.append("  goto :depbot_invocation_count_known\r\n");
                    script.append(")\r\n");
                }
                script.append(":depbot_invocation_count_known\r\n");
                for (Map.Entry<Integer, Map<String, Path>> entry
                        : new java.util.TreeMap<>(invocationCreateSources).entrySet()) {
                    script.append("if \"%DEPBOT_INVOCATION_COUNT%\"==\"").append(entry.getKey()).append("\" (\r\n");
                    for (Map.Entry<String, Path> fileEntry : entry.getValue().entrySet()) {
                        String parent = parentOf(fileEntry.getKey());
                        if (parent != null) {
                            script.append("  if not exist \"").append(parent).append("\" mkdir \"")
                                    .append(parent).append("\"\r\n");
                        }
                        script.append("  copy /y \"").append(fileEntry.getValue()).append("\" \"")
                                .append(fileEntry.getKey()).append("\" > nul\r\n");
                    }
                    script.append(")\r\n");
                }
            }
            if (snapshotSource != null) {
                // "copy" would fail the whole script noisily if the file is not there yet; the
                // test asserts on the snapshot, so a silent miss is caught by the assertion.
                script.append("copy /y \"").append(snapshotSource).append("\" \"")
                        .append(recordings.resolve("snapshot.txt")).append("\" > nul 2>&1\r\n");
            }
            for (Map.Entry<String, Path> entry : createSources.entrySet()) {
                String relativePath = entry.getKey();
                String parent = parentOf(relativePath);
                if (parent != null) {
                    script.append("if not exist \"").append(parent).append("\" mkdir \"").append(parent).append("\"\r\n");
                }
                script.append("copy /y \"").append(entry.getValue()).append("\" \"")
                        .append(relativePath).append("\" > nul\r\n");
            }
            for (String relativePath : filesToDelete) {
                script.append("del /f /q \"").append(relativePath).append("\"\r\n");
            }

            Path stdinFile = recordings.resolve("stdin.txt");
            Path phaseSequence = recordings.resolve("phase-sequence.txt");
            // Stdin is captured, and a finalization call is recognised, before any configured sleep --
            // a finalization call must complete quickly regardless of what the primary call was told to
            // do, since it is a separate, later process invocation with its own short prompt.
            script.append("more > \"").append(stdinFile).append("\"\r\n");
            for (FinalizationKind kind : FINALIZATION_KINDS) {
                script.append("findstr /c:\"").append(kind.markerBody()).append("\" \"")
                        .append(stdinFile).append("\" > nul\r\n");
                script.append("if not errorlevel 1 goto :depbot_finalization_").append(kind.key())
                        .append("\r\n");
            }

            if (sleepSeconds > 0) {
                // ping, not timeout: timeout needs a console and fails when stdin is redirected.
                // Its own output goes to nul so it never inherits (and holds open) the redirected
                // stdout file, which would block temp-directory cleanup after a forced kill.
                script.append("ping -n ").append(sleepSeconds + 1).append(" 127.0.0.1 > nul 2>&1\r\n");
            }

            // Detection happens after stdin is captured, since the marker is in the prompt itself.
            // "if not errorlevel 1" is cmd's way of saying "errorlevel is 0", i.e. findstr matched.
            for (ClaudePhase phase : detectionOrder()) {
                script.append("findstr /c:\"").append(markerBody(phase)).append("\" \"")
                        .append(stdinFile).append("\" > nul\r\n");
                script.append("if not errorlevel 1 goto :depbot_").append(phase.directoryName())
                        .append("\r\n");
            }
            script.append("goto :depbot_default\r\n");

            for (FinalizationKind kind : FINALIZATION_KINDS) {
                Path kindStdout = finalizationStdouts.get(kind);
                PhaseResponse kindResponse = finalizationResponses.get(kind);
                script.append(":depbot_finalization_").append(kind.key()).append("\r\n");
                script.append("echo ").append(kind.sequenceLabel()).append(">> \"")
                        .append(phaseSequence).append("\"\r\n");
                script.append("type \"").append(kindStdout == null ? canned : kindStdout).append("\"\r\n");
                script.append("type \"").append(cannedError).append("\" 1>&2\r\n");
                script.append("exit /b ")
                        .append(kindResponse == null ? exitCode : kindResponse.exitCode()).append("\r\n");
            }

            for (ClaudePhase phase : ClaudePhase.values()) {
                PhaseResponse response = phaseResponses.get(phase);
                script.append(":depbot_").append(phase.directoryName()).append("\r\n");
                script.append("echo ").append(phase.directoryName()).append(">> \"")
                        .append(phaseSequence).append("\"\r\n");
                for (Map.Entry<String, Path> entry
                        : phaseCreateSources.getOrDefault(phase, Map.of()).entrySet()) {
                    String parent = parentOf(entry.getKey());
                    if (parent != null) {
                        script.append("if not exist \"").append(parent).append("\" mkdir \"")
                                .append(parent).append("\"\r\n");
                    }
                    script.append("copy /y \"").append(entry.getValue()).append("\" \"")
                            .append(entry.getKey()).append("\" > nul\r\n");
                }
                for (String commandLine : phaseGitCommands.getOrDefault(phase, List.of())) {
                    // Redirected away: git's own confirmation output would otherwise land in front of
                    // the canned JSON response on the same stdout stream Claude's answer is read from.
                    script.append("git ").append(commandLine).append(" > nul 2>&1\r\n");
                }
                script.append("type \"").append(phaseStdout.getOrDefault(phase, canned)).append("\"\r\n");
                script.append("type \"").append(cannedError).append("\" 1>&2\r\n");
                script.append("exit /b ")
                        .append(response == null ? exitCode : response.exitCode()).append("\r\n");
            }

            script.append(":depbot_default\r\n");
            script.append("echo ").append(NO_PHASE).append(">> \"").append(phaseSequence).append("\"\r\n");
            script.append("type \"").append(canned).append("\"\r\n");
            script.append("type \"").append(cannedError).append("\" 1>&2\r\n");
            script.append("exit /b ").append(exitCode).append("\r\n");
            return script.toString();
        }

        private String posixScript(
                Path recordings, Path canned, Path cannedError,
                Map<String, Path> createSources, Map<ClaudePhase, Path> phaseStdout,
                Map<ClaudePhase, Map<String, Path>> phaseCreateSources,
                Map<FinalizationKind, Path> finalizationStdouts,
                Map<Integer, Map<String, Path>> invocationCreateSources) {

            StringBuilder script = new StringBuilder();
            script.append("#!/bin/sh\n");
            Path invocations = recordings.resolve("invocations.txt");
            script.append("echo invoked >> '").append(invocations).append("'\n");
            script.append("printf '%s\\n' \"$*\" > '").append(recordings.resolve("args.txt")).append("'\n");
            script.append("pwd > '").append(recordings.resolve("cwd.txt")).append("'\n");
            script.append("git rev-parse --abbrev-ref HEAD >> '")
                    .append(recordings.resolve("branch-sequence.txt")).append("' 2>/dev/null\n");
            if (!invocationCreateSources.isEmpty()) {
                // Marker files, not a piped line count -- mirrors the Windows script's own reasoning.
                // Counting is done in two steps, both by marker existence alone: first, which call this
                // is overall -- one marker consumed per call, in order, regardless of phase, so a
                // read-only call still advances the count; then, which configured file set (if any)
                // belongs to that exact call number.
                int maxOrdinal = java.util.Collections.max(invocationCreateSources.keySet());
                script.append("DEPBOT_INVOCATION_COUNT=0\n");
                for (int callNumber = 1; callNumber <= maxOrdinal; callNumber++) {
                    Path countMarker = recordings.resolve("invocation-count-" + callNumber + ".marker");
                    script.append("if [ \"$DEPBOT_INVOCATION_COUNT\" = \"0\" ] && [ ! -f '")
                            .append(countMarker).append("' ]; then\n");
                    script.append("  touch '").append(countMarker).append("'\n");
                    script.append("  DEPBOT_INVOCATION_COUNT=").append(callNumber).append("\n");
                    script.append("fi\n");
                }
                for (Map.Entry<Integer, Map<String, Path>> entry
                        : new java.util.TreeMap<>(invocationCreateSources).entrySet()) {
                    script.append("if [ \"$DEPBOT_INVOCATION_COUNT\" = \"").append(entry.getKey())
                            .append("\" ]; then\n");
                    for (Map.Entry<String, Path> fileEntry : entry.getValue().entrySet()) {
                        String parent = parentOf(fileEntry.getKey());
                        if (parent != null) {
                            script.append("  mkdir -p '").append(parent).append("'\n");
                        }
                        script.append("  cp '").append(fileEntry.getValue()).append("' '")
                                .append(fileEntry.getKey()).append("'\n");
                    }
                    script.append("fi\n");
                }
            }
            if (snapshotSource != null) {
                script.append("cp '").append(snapshotSource).append("' '")
                        .append(recordings.resolve("snapshot.txt")).append("' 2>/dev/null\n");
            }
            for (Map.Entry<String, Path> entry : createSources.entrySet()) {
                String relativePath = entry.getKey();
                String parent = parentOf(relativePath);
                if (parent != null) {
                    script.append("mkdir -p '").append(parent).append("'\n");
                }
                script.append("cp '").append(entry.getValue()).append("' '").append(relativePath).append("'\n");
            }
            for (String relativePath : filesToDelete) {
                script.append("rm -f '").append(relativePath).append("'\n");
            }

            Path stdinFile = recordings.resolve("stdin.txt");
            Path phaseSequence = recordings.resolve("phase-sequence.txt");
            // Stdin is captured, and a finalization call is recognised, before any configured sleep --
            // a finalization call must complete quickly regardless of what the primary call was told to
            // do, since it is a separate, later process invocation with its own short prompt.
            script.append("cat > '").append(stdinFile).append("'\n");
            for (FinalizationKind kind : FINALIZATION_KINDS) {
                Path kindStdout = finalizationStdouts.get(kind);
                PhaseResponse kindResponse = finalizationResponses.get(kind);
                script.append("if grep -q '").append(kind.markerBody()).append("' '")
                        .append(stdinFile).append("'; then\n");
                script.append("  echo ").append(kind.sequenceLabel()).append(" >> '")
                        .append(phaseSequence).append("'\n");
                script.append("  cat '").append(kindStdout == null ? canned : kindStdout).append("'\n");
                script.append("  cat '").append(cannedError).append("' >&2\n");
                script.append("  exit ")
                        .append(kindResponse == null ? exitCode : kindResponse.exitCode()).append("\n");
                script.append("fi\n");
            }

            if (sleepSeconds > 0) {
                script.append("sleep ").append(sleepSeconds).append("\n");
            }

            for (ClaudePhase phase : detectionOrder()) {
                PhaseResponse response = phaseResponses.get(phase);
                script.append("if grep -q '").append(markerBody(phase)).append("' '")
                        .append(stdinFile).append("'; then\n");
                script.append("  echo ").append(phase.directoryName()).append(" >> '")
                        .append(phaseSequence).append("'\n");
                for (Map.Entry<String, Path> entry
                        : phaseCreateSources.getOrDefault(phase, Map.of()).entrySet()) {
                    String parent = parentOf(entry.getKey());
                    if (parent != null) {
                        script.append("  mkdir -p '").append(parent).append("'\n");
                    }
                    script.append("  cp '").append(entry.getValue()).append("' '")
                            .append(entry.getKey()).append("'\n");
                }
                for (String commandLine : phaseGitCommands.getOrDefault(phase, List.of())) {
                    // Redirected away: git's own confirmation output would otherwise land in front of
                    // the canned JSON response on the same stdout stream Claude's answer is read from.
                    script.append("  git ").append(commandLine).append(" > /dev/null 2>&1\n");
                }
                script.append("  cat '").append(phaseStdout.getOrDefault(phase, canned)).append("'\n");
                script.append("  cat '").append(cannedError).append("' >&2\n");
                script.append("  exit ").append(response == null ? exitCode : response.exitCode()).append("\n");
                script.append("fi\n");
            }

            script.append("echo ").append(NO_PHASE).append(" >> '").append(phaseSequence).append("'\n");
            script.append("cat '").append(canned).append("'\n");
            script.append("cat '").append(cannedError).append("' >&2\n");
            script.append("exit ").append(exitCode).append("\n");
            return script.toString();
        }

        /**
         * Human review before implementation before assessment. An implementation prompt legitimately
         * quotes the assessment it is carrying out, so it is the one prompt that could contain both
         * markers; checking the more specific phase first means it is never mistaken for the earlier
         * one. A human review prompt may likewise quote the analysis it was handed, so it is checked
         * first of all.
         */
        private static List<ClaudePhase> detectionOrder() {
            return List.of(ClaudePhase.HUMAN_REVIEW, ClaudePhase.IMPLEMENTATION, ClaudePhase.ASSESSMENT);
        }

        /**
         * The searchable part of a phase marker, without the HTML comment punctuation.
         * {@code findstr /c:} and {@code grep} both take it as a literal, and {@code <}/{@code >}
         * would be redirection operators in both shells if they were included.
         */
        private static String markerBody(ClaudePhase phase) {
            return ClaudePhase.MARKER_PREFIX + " " + phase.name();
        }

        /** The parent directory portion of a relative path, using {@code /} as the separator on every OS. */
        private static String parentOf(String relativePath) {
            String normalized = relativePath.replace('\\', '/');
            int lastSlash = normalized.lastIndexOf('/');
            return lastSlash < 0 ? null : normalized.substring(0, lastSlash);
        }

        private record PhaseResponse(String stdout, int exitCode) {
        }
    }
}
