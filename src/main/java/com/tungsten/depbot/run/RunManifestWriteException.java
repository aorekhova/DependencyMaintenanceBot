package com.tungsten.depbot.run;

/** The run manifest or one of its task files could not be written. Messages name paths only. */
public class RunManifestWriteException extends RuntimeException {

    public RunManifestWriteException(String safeMessage, Throwable cause) {
        super(safeMessage, cause);
    }
}
