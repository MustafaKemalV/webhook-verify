package io.github.mustafakemalv.webhookverify.core;

/**
 * Strategy that verifies the signature of an inbound webhook for a single provider.
 * Implementations are stateless and are selected by {@link #provider()}.
 */
public interface WebhookVerifier {

    /** Provider id this verifier handles, e.g. "stripe", "github", "generic-hmac". */
    String provider();

    /**
     * Verifies the request signature. Never throws for an invalid signature;
     * returns a failing {@link VerificationResult} instead.
     */
    VerificationResult verify(VerificationContext context);
}
