package io.github.mustafakemalv.webhookverify.autoconfigure;

import io.github.mustafakemalv.webhookverify.observability.WebhookVerificationMetrics;
import io.github.mustafakemalv.webhookverify.web.CachedBodyFilter;
import io.github.mustafakemalv.webhookverify.web.DefaultWebhookVerificationFailureHandler;
import io.github.mustafakemalv.webhookverify.web.WebhookVerificationFailureHandler;
import io.github.mustafakemalv.webhookverify.web.WebhookVerificationInterceptor;
import java.time.Clock;
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
 * Wires webhook-verify into a Spring MVC (servlet) application: registers the raw-body caching
 * filter first and installs the verification interceptor built from the shared verifier strategies.
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
    @ConditionalOnMissingBean
    WebhookVerificationMetrics webhookVerificationMetrics() {
        return WebhookVerificationMetrics.NO_OP;
    }

    @Bean
    WebhookVerificationInterceptor webhookVerificationInterceptor(
            WebhookVerifyProperties properties, Clock clock,
            WebhookVerificationFailureHandler failureHandler,
            WebhookVerificationMetrics metrics) {
        return new WebhookVerificationInterceptor(
                WebhookVerifiers.build(properties), properties, clock, failureHandler, metrics);
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
}
