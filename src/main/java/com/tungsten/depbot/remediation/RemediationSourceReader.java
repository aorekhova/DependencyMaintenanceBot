package com.tungsten.depbot.remediation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.report.actionable.ActionableReport;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Reads back the two documents earlier commands published: the actionable report from {@code scan} and the
 * plan from {@code plan-remediation}.
 *
 * <p>Both are read rather than passed in memory from the preceding stage, deliberately. It means the
 * remediation run consumes exactly the files a human can open and an operator can inspect afterwards, so
 * there is no possibility of the run acting on data that differs from what was published.
 */
public final class RemediationSourceReader {

    private final Path actionableReportPath;
    private final Path planPath;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public RemediationSourceReader(Path actionableReportPath, Path planPath) {
        this.actionableReportPath = Objects.requireNonNull(actionableReportPath, "actionableReportPath");
        this.planPath = Objects.requireNonNull(planPath, "planPath");
    }

    /** @throws RemediationSourceException if it is missing or cannot be understood */
    public ActionableReport readActionableReport() {
        return read(actionableReportPath, ActionableReport.class, "an actionable report", "scan");
    }

    /** @throws RemediationSourceException if it is missing or cannot be understood */
    public RemediationPlan readPlan() {
        return read(planPath, RemediationPlan.class, "a remediation plan", "plan-remediation");
    }

    private <T> T read(Path path, Class<T> type, String description, String producingCommand) {
        if (!Files.exists(path)) {
            throw new RemediationSourceException(
                    "Could not find " + path + ". Run \"" + producingCommand + "\" first to produce it.");
        }
        String content;
        try {
            content = Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RemediationSourceException("Could not read " + path, e);
        }
        try {
            return mapper.readValue(content, type);
        } catch (JsonProcessingException e) {
            throw new RemediationSourceException("Could not parse " + path + " as " + description, e);
        }
    }
}
