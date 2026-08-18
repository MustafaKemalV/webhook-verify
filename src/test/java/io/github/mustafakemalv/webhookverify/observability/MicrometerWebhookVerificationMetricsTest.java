package io.github.mustafakemalv.webhookverify.observability;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.mustafakemalv.webhookverify.core.FailureReason;
import io.github.mustafakemalv.webhookverify.core.VerificationResult;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

class MicrometerWebhookVerificationMetricsTest {

    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final MicrometerWebhookVerificationMetrics metrics =
            new MicrometerWebhookVerificationMetrics(registry);

    @Test
    void counts_a_successful_verification() {
        metrics.record("stripe", VerificationResult.ok());

        double count = registry.get("webhook.verify")
                .tag("provider", "stripe")
                .tag("outcome", "success")
                .tag("reason", "NONE")
                .counter().count();

        assertThat(count).isEqualTo(1.0);
    }

    @Test
    void counts_a_failed_verification_with_reason() {
        metrics.record("github", VerificationResult.fail(FailureReason.SIGNATURE_MISMATCH));

        double count = registry.get("webhook.verify")
                .tag("provider", "github")
                .tag("outcome", "failure")
                .tag("reason", "SIGNATURE_MISMATCH")
                .counter().count();

        assertThat(count).isEqualTo(1.0);
    }
}
