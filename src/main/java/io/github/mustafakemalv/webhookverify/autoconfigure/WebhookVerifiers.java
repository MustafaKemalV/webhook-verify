package io.github.mustafakemalv.webhookverify.autoconfigure;

import io.github.mustafakemalv.webhookverify.core.WebhookVerifier;
import io.github.mustafakemalv.webhookverify.provider.GenericHmacVerifier;
import io.github.mustafakemalv.webhookverify.provider.GitHubVerifier;
import io.github.mustafakemalv.webhookverify.provider.PaddleVerifier;
import io.github.mustafakemalv.webhookverify.provider.StripeVerifier;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds one {@link WebhookVerifier} per configured provider. Shared by the servlet and reactive
 * auto-configurations so the provider-to-verifier mapping lives in a single place.
 */
final class WebhookVerifiers {

    private WebhookVerifiers() {
    }

    static Map<String, WebhookVerifier> build(WebhookVerifyProperties properties) {
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
