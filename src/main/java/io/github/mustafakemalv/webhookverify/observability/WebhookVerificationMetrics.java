package io.github.mustafakemalv.webhookverify.observability;

import io.github.mustafakemalv.webhookverify.core.VerificationResult;

/**
 * Records the outcome of each webhook verification. The default is no-op; a Micrometer-backed
 * implementation is wired automatically when Micrometer and a MeterRegistry are on the classpath.
 */
@FunctionalInterface
public interface WebhookVerificationMetrics {

    WebhookVerificationMetrics NO_OP = (provider, result) -> {
    };

    void record(String provider, VerificationResult result);
}
