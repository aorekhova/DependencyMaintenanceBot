package com.tungsten.depbot.git;

/**
 * The repository was not in a safe starting state: either the working tree was not clean, or a
 * git operation (merge, cherry-pick, rebase) was left in progress. Nothing was created, checked
 * out, or changed before this was raised.
 */
public class DirtyCheckoutException extends RuntimeException {

    public DirtyCheckoutException(String message) {
        super(message);
    }
}
