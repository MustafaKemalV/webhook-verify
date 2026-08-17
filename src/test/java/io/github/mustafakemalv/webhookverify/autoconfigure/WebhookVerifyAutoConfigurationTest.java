package io.github.mustafakemalv.webhookverify.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.mustafakemalv.webhookverify.web.WebhookVerificationInterceptor;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

class WebhookVerifyAutoConfigurationTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(WebhookVerifyAutoConfiguration.class));

    @Test
    void registers_interceptor_and_filter_when_a_provider_is_configured() {
        runner.withPropertyValues(
                        "webhook-verify.providers.stripe.type=stripe",
                        "webhook-verify.providers.stripe.secret=whsec_x")
                .run(context -> {
                    assertThat(context).hasSingleBean(WebhookVerificationInterceptor.class);
                    assertThat(context).hasBean("cachedBodyFilterRegistration");
                });
    }

    @Test
    void fails_fast_when_generic_provider_missing_signature_header() {
        runner.withPropertyValues(
                        "webhook-verify.providers.partner.type=generic-hmac",
                        "webhook-verify.providers.partner.secret=s3cr3t")
                .run(context -> assertThat(context).hasFailed());
    }
}
