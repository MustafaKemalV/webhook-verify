package io.github.mustafakemalv.webhookverify.core;

/** Why a webhook signature verification failed. */
public enum FailureReason {
    NONE,
    MISSING_SIGNATURE,
    MALFORMED_SIGNATURE,
    SIGNATURE_MISMATCH,
    TIMESTAMP_OUT_OF_TOLERANCE
}
