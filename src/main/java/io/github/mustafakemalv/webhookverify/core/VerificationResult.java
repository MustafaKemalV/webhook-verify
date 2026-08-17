package io.github.mustafakemalv.webhookverify.core;

/** Outcome of a verification: valid, or invalid with a specific reason. */
public record VerificationResult(boolean valid, FailureReason reason) {

    private static final VerificationResult OK = new VerificationResult(true, FailureReason.NONE);

    public static VerificationResult ok() {
        return OK;
    }

    public static VerificationResult fail(FailureReason reason) {
        return new VerificationResult(false, reason);
    }
}
