package io.github.mustafakemalv.webhookverify.webflux;

import io.github.mustafakemalv.webhookverify.VerifiedWebhook;
import io.github.mustafakemalv.webhookverify.autoconfigure.WebhookVerifyProperties;
import io.github.mustafakemalv.webhookverify.core.VerificationContext;
import io.github.mustafakemalv.webhookverify.core.VerificationResult;
import io.github.mustafakemalv.webhookverify.core.WebhookVerifier;
import io.github.mustafakemalv.webhookverify.observability.WebhookVerificationMetrics;
import java.time.Clock;
import java.util.Map;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.http.HttpStatus;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Reactive counterpart of the servlet interceptor + filter: for handlers annotated with
 * {@link VerifiedWebhook}, it captures the raw body once, verifies the signature, records metrics,
 * and either forwards the (replayable) request downstream or completes with 401. Requests without
 * the annotation pass through untouched, so their bodies are never buffered.
 */
public class ReactiveWebhookVerificationWebFilter implements WebFilter {

    // Sentinel emitted when getHandler() is empty (no mapped handler). It lets us resolve the
    // "no handler" case inside getHandler's own stream, so switchIfEmpty is not needed: the
    // downstream flatMap always returns a Mono<Void>, and switchIfEmpty on a Mono<Void> would
    // fire on every request (it always completes empty) and run the chain a second time.
    private static final Object NO_MATCHING_HANDLER = new Object();

    private final RequestMappingHandlerMapping handlerMapping;
    private final Map<String, WebhookVerifier> verifiersByProvider;
    private final WebhookVerifyProperties properties;
    private final Clock clock;
    private final WebhookVerificationMetrics metrics;

    public ReactiveWebhookVerificationWebFilter(RequestMappingHandlerMapping handlerMapping,
            Map<String, WebhookVerifier> verifiersByProvider, WebhookVerifyProperties properties,
            Clock clock, WebhookVerificationMetrics metrics) {
        this.handlerMapping = handlerMapping;
        this.verifiersByProvider = verifiersByProvider;
        this.properties = properties;
        this.clock = clock;
        this.metrics = metrics;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return handlerMapping.getHandler(exchange)
                .defaultIfEmpty(NO_MATCHING_HANDLER)
                .flatMap(handler -> {
                    if (handler == NO_MATCHING_HANDLER) {
                        return chain.filter(exchange);
                    }
                    VerifiedWebhook annotation = annotation(handler);
                    return annotation == null
                            ? chain.filter(exchange)
                            : verify(exchange, chain, annotation);
                });
    }

    private static VerifiedWebhook annotation(Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return null;
        }
        VerifiedWebhook annotation = AnnotatedElementUtils.findMergedAnnotation(
                handlerMethod.getMethod(), VerifiedWebhook.class);
        if (annotation == null) {
            annotation = AnnotatedElementUtils.findMergedAnnotation(
                    handlerMethod.getBeanType(), VerifiedWebhook.class);
        }
        return annotation;
    }

    private Mono<Void> verify(ServerWebExchange exchange, WebFilterChain chain, VerifiedWebhook annotation) {
        String providerId = annotation.provider();
        WebhookVerifier verifier = verifiersByProvider.get(providerId);
        WebhookVerifyProperties.Provider config = properties.getProviders().get(providerId);
        if (verifier == null || config == null || config.getSecret() == null) {
            return Mono.error(new IllegalStateException(
                    "No webhook-verify configuration for provider '" + providerId + "'"));
        }
        return CachedBodyServerHttpRequest.capture(exchange).flatMap(cached -> {
            VerificationContext context = new VerificationContext(
                    cached.getCachedBody(),
                    name -> cached.getHeaders().getFirst(name),
                    config.getSecret(), config.getTolerance(), clock.instant());
            VerificationResult result = verifier.verify(context);
            metrics.record(providerId, result);
            if (result.valid()) {
                return chain.filter(exchange.mutate().request(cached).build());
            }
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        });
    }
}
