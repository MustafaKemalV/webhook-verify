package io.github.mustafakemalv.webhookverify.observability;

import io.github.mustafakemalv.webhookverify.core.VerificationResult;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Micrometer-backed metrics: increments the {@code webhook.verify} counter tagged by
 * {@code provider}, {@code outcome} (success/failure) and {@code reason}.
 */
public class MicrometerWebhookVerificationMetrics implements WebhookVerificationMetrics {

    private final MeterRegistry registry;

    public MicrometerWebhookVerificationMetrics(MeterRegistry registry) {
        this.registry = registry;
    }

    @Override
    public void record(String provider, VerificationResult result) {
        Counter.builder("webhook.verify")
                .tag("provider", provider)
                .tag("outcome", result.valid() ? "success" : "failure")
                .tag("reason", result.reason().name())
                .register(registry)
                .increment();
    }
}
