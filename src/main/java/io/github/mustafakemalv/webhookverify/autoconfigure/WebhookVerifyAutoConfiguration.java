package io.github.mustafakemalv.webhookverify.autoconfigure;

import io.github.mustafakemalv.webhookverify.core.WebhookVerifier;
import io.github.mustafakemalv.webhookverify.provider.GenericHmacVerifier;
import io.github.mustafakemalv.webhookverify.provider.GitHubVerifier;
import io.github.mustafakemalv.webhookverify.provider.PaddleVerifier;
import io.github.mustafakemalv.webhookverify.provider.StripeVerifier;
import io.github.mustafakemalv.webhookverify.web.CachedBodyFilter;
import io.github.mustafakemalv.webhookverify.web.DefaultWebhookVerificationFailureHandler;
import io.github.mustafakemalv.webhookverify.web.WebhookVerificationFailureHandler;
import io.github.mustafakemalv.webhookverify.web.WebhookVerificationInterceptor;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Wires webhook-verify into a Spring MVC application: builds one verifier per configured provider,
 * registers the raw-body caching filter first, and installs the verification interceptor.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(WebhookVerifyProperties.class)
public class WebhookVerifyAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    Clock webhookVerifyClock() {
        return Clock.systemUTC();
    }

    @Bean
    @ConditionalOnMissingBean
    WebhookVerificationFailureHandler webhookVerificationFailureHandler() {
        return new DefaultWebhookVerificationFailureHandler();
    }

    @Bean
    WebhookVerificationInterceptor webhookVerificationInterceptor(
            WebhookVerifyProperties properties, Clock clock,
            WebhookVerificationFailureHandler failureHandler) {
        return new WebhookVerificationInterceptor(buildVerifiers(properties), properties, clock, failureHandler);
    }

    @Bean
    FilterRegistrationBean<CachedBodyFilter> cachedBodyFilterRegistration() {
        FilterRegistrationBean<CachedBodyFilter> registration =
                new FilterRegistrationBean<>(new CachedBodyFilter());
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }

    @Bean
    WebMvcConfigurer webhookVerifyMvcConfigurer(WebhookVerificationInterceptor interceptor) {
        return new WebMvcConfigurer() {
            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                registry.addInterceptor(interceptor);
            }
        };
    }

    private static Map<String, WebhookVerifier> buildVerifiers(WebhookVerifyProperties properties) {
        Map<String, WebhookVerifier> verifiers = new LinkedHashMap<>();
        properties.getProviders().forEach((id, provider) -> {
            String type = provider.getType();
            WebhookVerifier verifier = switch (type == null ? "" : type) {
                case "stripe" -> new StripeVerifier();
                case "github" -> new GitHubVerifier();
                case "paddle" -> new PaddleVerifier();
                case "generic-hmac" -> new GenericHmacVerifier(
                        requireSignatureHeader(id, provider), provider.getEncoding());
                default -> throw new IllegalStateException(
                        "Unknown webhook-verify provider type '" + type + "' for provider '" + id + "'");
            };
            verifiers.put(id, verifier);
        });
        return verifiers;
    }

    private static String requireSignatureHeader(String id, WebhookVerifyProperties.Provider provider) {
        String header = provider.getSignatureHeader();
        if (header == null || header.isBlank()) {
            throw new IllegalStateException(
                    "Provider '" + id + "' of type generic-hmac requires 'signature-header'");
        }
        return header;
    }
}
