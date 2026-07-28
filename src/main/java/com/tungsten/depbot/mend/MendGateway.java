package com.tungsten.depbot.mend;

import com.tungsten.depbot.config.EnvConfig;
import com.tungsten.depbot.mend.model.VulnerabilityReport;

/**
 * Source of a Mend vulnerability report.
 *
 * <p>This seam exists so the scan orchestration can be unit-tested with a small fake instead of
 * a real socket or a subclassed HTTP client. It is the only interface in this slice.
 *
 * <p>The whole {@link EnvConfig} is passed rather than two loose strings so the credential pair
 * travels together and the arguments cannot be transposed.
 *
 * <p>Failures are reported through the unchecked {@link MendApiException},
 * {@link MendHttpException} and {@link MalformedResponseException}.
 */
public interface MendGateway {

    VulnerabilityReport fetchVulnerabilityReport(EnvConfig config);
}
