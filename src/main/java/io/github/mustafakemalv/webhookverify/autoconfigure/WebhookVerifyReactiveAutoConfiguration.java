package io.github.mustafakemalv.webhookverify.autoconfigure;

import io.github.mustafakemalv.webhookverify.observability.WebhookVerificationMetrics;
import io.github.mustafakemalv.webhookverify.webflux.ReactiveWebhookVerificationWebFilter;
import java.time.Clock;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerMapping;

/**
 * Wires webhook-verify into a Spring WebFlux (reactive) application: installs a single WebFilter
 * that verifies {@code @VerifiedWebhook} handlers using the shared verifier strategies.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@EnableConfigurationProperties(WebhookVerifyProperties.class)
public class WebhookVerifyReactiveAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    Clock webhookVerifyClock() {
        return Clock.systemUTC();
    }

    @Bean
    @ConditionalOnMissingBean
    WebhookVerificationMetrics webhookVerificationMetrics() {
        return WebhookVerificationMetrics.NO_OP;
    }

    @Bean
    ReactiveWebhookVerificationWebFilter reactiveWebhookVerificationWebFilter(
            RequestMappingHandlerMapping requestMappingHandlerMapping,
            WebhookVerifyProperties properties, Clock clock, WebhookVerificationMetrics metrics) {
        return new ReactiveWebhookVerificationWebFilter(requestMappingHandlerMapping,
                WebhookVerifiers.build(properties), properties, clock, metrics);
    }
}
