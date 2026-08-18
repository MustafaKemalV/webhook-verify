package io.github.mustafakemalv.webhookverify.autoconfigure;

import io.github.mustafakemalv.webhookverify.observability.MicrometerWebhookVerificationMetrics;
import io.github.mustafakemalv.webhookverify.observability.WebhookVerificationMetrics;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Wires Micrometer-backed webhook metrics when Micrometer and a {@link MeterRegistry} are present.
 * Evaluated before {@link WebhookVerifyAutoConfiguration} so that its no-op metrics default only
 * applies when this Micrometer-backed bean is absent.
 */
@AutoConfiguration(before = WebhookVerifyAutoConfiguration.class)
@ConditionalOnClass(MeterRegistry.class)
public class WebhookVerifyMetricsAutoConfiguration {

    @Bean
    @ConditionalOnBean(MeterRegistry.class)
    @ConditionalOnMissingBean
    WebhookVerificationMetrics micrometerWebhookVerificationMetrics(MeterRegistry registry) {
        return new MicrometerWebhookVerificationMetrics(registry);
    }
}
