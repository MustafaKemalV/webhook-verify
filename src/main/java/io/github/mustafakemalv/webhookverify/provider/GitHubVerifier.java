package io.github.mustafakemalv.webhookverify.provider;

import io.github.mustafakemalv.webhookverify.core.FailureReason;
import io.github.mustafakemalv.webhookverify.core.Hmac;
import io.github.mustafakemalv.webhookverify.core.VerificationContext;
import io.github.mustafakemalv.webhookverify.core.VerificationResult;
import io.github.mustafakemalv.webhookverify.core.WebhookVerifier;
import java.nio.charset.StandardCharsets;

/**
 * GitHub webhook verifier. GitHub sends {@code X-Hub-Signature-256: sha256=<hex>} where the
 * hex is HMAC-SHA256 of the raw request body under the webhook secret.
 */
public final class GitHubVerifier implements WebhookVerifier {

    public static final String PROVIDER = "github";

    private static final String SIGNATURE_HEADER = "X-Hub-Signature-256";
    private static final String PREFIX = "sha256=";

    @Override
    public String provider() {
        return PROVIDER;
    }

    @Override
    public VerificationResult verify(VerificationContext context) {
        String provided = context.header(SIGNATURE_HEADER);
        if (provided == null || provided.isBlank()) {
            return VerificationResult.fail(FailureReason.MISSING_SIGNATURE);
        }
        String trimmed = provided.trim();
        if (!trimmed.startsWith(PREFIX)) {
            return VerificationResult.fail(FailureReason.MALFORMED_SIGNATURE);
        }
        String expected = PREFIX + Hmac.hex(
                Hmac.sha256(context.secret().getBytes(StandardCharsets.UTF_8), context.rawBody()));
        return Hmac.constantTimeEquals(expected, trimmed)
                ? VerificationResult.ok()
                : VerificationResult.fail(FailureReason.SIGNATURE_MISMATCH);
    }
}
