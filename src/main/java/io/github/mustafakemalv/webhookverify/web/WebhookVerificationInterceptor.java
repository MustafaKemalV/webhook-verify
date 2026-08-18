package io.github.mustafakemalv.webhookverify.web;

import io.github.mustafakemalv.webhookverify.autoconfigure.WebhookVerifyProperties;
import io.github.mustafakemalv.webhookverify.core.VerificationContext;
import io.github.mustafakemalv.webhookverify.core.VerificationResult;
import io.github.mustafakemalv.webhookverify.core.WebhookVerifier;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.util.Map;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Enforces {@link VerifiedWebhook} on controller handlers: reads the annotation, looks up the
 * matching verifier and secret, verifies the raw (cached) body, and on a missing or invalid
 * signature delegates to a {@link WebhookVerificationFailureHandler} (401 by default) so the
 * handler never runs.
 */
public class WebhookVerificationInterceptor implements HandlerInterceptor {

    private final Map<String, WebhookVerifier> verifiersByProvider;
    private final WebhookVerifyProperties properties;
    private final Clock clock;
    private final WebhookVerificationFailureHandler failureHandler;

    public WebhookVerificationInterceptor(Map<String, WebhookVerifier> verifiersByProvider,
            WebhookVerifyProperties properties, Clock clock,
            WebhookVerificationFailureHandler failureHandler) {
        this.verifiersByProvider = verifiersByProvider;
        this.properties = properties;
        this.clock = clock;
        this.failureHandler = failureHandler;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }
        VerifiedWebhook annotation = AnnotatedElementUtils.findMergedAnnotation(
                handlerMethod.getMethod(), VerifiedWebhook.class);
        if (annotation == null) {
            annotation = AnnotatedElementUtils.findMergedAnnotation(
                    handlerMethod.getBeanType(), VerifiedWebhook.class);
        }
        if (annotation == null) {
            return true;
        }

        String providerId = annotation.provider();
        WebhookVerifier verifier = verifiersByProvider.get(providerId);
        WebhookVerifyProperties.Provider config = properties.getProviders().get(providerId);
        if (verifier == null || config == null || config.getSecret() == null) {
            throw new IllegalStateException(
                    "No webhook-verify configuration for provider '" + providerId + "'");
        }

        byte[] rawBody = rawBody(request);
        VerificationContext context = new VerificationContext(
                rawBody, request::getHeader, config.getSecret(),
                config.getTolerance(), clock.instant());

        VerificationResult result = verifier.verify(context);
        if (result.valid()) {
            return true;
        }
        failureHandler.handle(request, response, providerId, result.reason());
        return false;
    }

    private static byte[] rawBody(HttpServletRequest request) throws IOException {
        if (request instanceof CachedBodyHttpServletRequest cached) {
            return cached.getCachedBody();
        }
        return request.getInputStream().readAllBytes();
    }
}
