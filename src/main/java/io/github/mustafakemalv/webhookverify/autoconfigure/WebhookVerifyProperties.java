package io.github.mustafakemalv.webhookverify.autoconfigure;

import io.github.mustafakemalv.webhookverify.core.SignatureEncoding;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Binds {@code webhook-verify.*} configuration. Each entry under {@code providers} maps a provider
 * id (the value used in {@code @VerifiedWebhook(provider = "...")}) to its secret, signing type
 * and options.
 */
@ConfigurationProperties(prefix = "webhook-verify")
public class WebhookVerifyProperties {

    /** Provider id -> settings. The id is what {@code @VerifiedWebhook(provider=...)} refers to. */
    private Map<String, Provider> providers = new LinkedHashMap<>();

    public Map<String, Provider> getProviders() {
        return providers;
    }

    public void setProviders(Map<String, Provider> providers) {
        this.providers = providers;
    }

    /** Per-provider settings. */
    public static class Provider {

        /** Which verifier to use: "stripe", "github", "paddle" or "generic-hmac". */
        private String type;

        /** Shared signing secret for this provider. */
        private String secret;

        /** Replay tolerance for time-based schemes (Stripe, Paddle). Defaults to 5 minutes. */
        private Duration tolerance = Duration.ofMinutes(5);

        /** Header carrying the signature; required only for the generic-hmac type. */
        private String signatureHeader;

        /** Signature encoding for the generic-hmac type: hex (default) or base64. */
        private SignatureEncoding encoding = SignatureEncoding.HEX;

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getSecret() {
            return secret;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }

        public Duration getTolerance() {
            return tolerance;
        }

        public void setTolerance(Duration tolerance) {
            this.tolerance = tolerance;
        }

        public String getSignatureHeader() {
            return signatureHeader;
        }

        public void setSignatureHeader(String signatureHeader) {
            this.signatureHeader = signatureHeader;
        }

        public SignatureEncoding getEncoding() {
            return encoding;
        }

        public void setEncoding(SignatureEncoding encoding) {
            this.encoding = encoding;
        }
    }
}
