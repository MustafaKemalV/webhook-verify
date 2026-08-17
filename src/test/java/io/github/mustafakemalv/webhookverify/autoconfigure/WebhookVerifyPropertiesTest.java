package io.github.mustafakemalv.webhookverify.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

class WebhookVerifyPropertiesTest {

    @Test
    void binds_providers_with_defaults_and_overrides() {
        Map<String, Object> source = new HashMap<>();
        source.put("webhook-verify.providers.stripe.type", "stripe");
        source.put("webhook-verify.providers.stripe.secret", "whsec_x");
        source.put("webhook-verify.providers.stripe.tolerance", "10m");
        source.put("webhook-verify.providers.partner.type", "generic-hmac");
        source.put("webhook-verify.providers.partner.secret", "s3cr3t");
        source.put("webhook-verify.providers.partner.signature-header", "X-Partner-Signature");

        WebhookVerifyProperties props = new Binder(new MapConfigurationPropertySource(source))
                .bind("webhook-verify", WebhookVerifyProperties.class)
                .get();

        WebhookVerifyProperties.Provider stripe = props.getProviders().get("stripe");
        assertThat(stripe.getType()).isEqualTo("stripe");
        assertThat(stripe.getSecret()).isEqualTo("whsec_x");
        assertThat(stripe.getTolerance()).isEqualTo(Duration.ofMinutes(10));

        WebhookVerifyProperties.Provider partner = props.getProviders().get("partner");
        assertThat(partner.getType()).isEqualTo("generic-hmac");
        assertThat(partner.getSignatureHeader()).isEqualTo("X-Partner-Signature");
        // default tolerance applied when not overridden
        assertThat(partner.getTolerance()).isEqualTo(Duration.ofMinutes(5));
    }
}
