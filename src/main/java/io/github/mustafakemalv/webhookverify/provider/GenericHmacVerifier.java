package io.github.mustafakemalv.webhookverify.provider;

import io.github.mustafakemalv.webhookverify.core.FailureReason;
import io.github.mustafakemalv.webhookverify.core.Hmac;
import io.github.mustafakemalv.webhookverify.core.SignatureEncoding;
import io.github.mustafakemalv.webhookverify.core.VerificationContext;
import io.github.mustafakemalv.webhookverify.core.VerificationResult;
import io.github.mustafakemalv.webhookverify.core.WebhookVerifier;
import java.nio.charset.StandardCharsets;

/**
 * Generic HMAC-SHA256 verifier: the signature is encode(HMAC-SHA256(secret, rawBody)) read from a
 * configurable header, where the encoding is hex (default) or base64. Use this for providers that
 * sign the raw body with a shared secret, such as Shopify (base64) or a custom internal webhook.
 */
public final class GenericHmacVerifier implements WebhookVerifier {

    public static final String PROVIDER = "generic-hmac";

    private final String signatureHeader;
    private final SignatureEncoding encoding;

    public GenericHmacVerifier(String signatureHeader) {
        this(signatureHeader, SignatureEncoding.HEX);
    }

    public GenericHmacVerifier(String signatureHeader, SignatureEncoding encoding) {
        this.signatureHeader = signatureHeader;
        this.encoding = encoding;
    }

    @Override
    public String provider() {
        return PROVIDER;
    }

    @Override
    public VerificationResult verify(VerificationContext context) {
        String provided = context.header(signatureHeader);
        if (provided == null || provided.isBlank()) {
            return VerificationResult.fail(FailureReason.MISSING_SIGNATURE);
        }
        String expected = encoding.encode(
                Hmac.sha256(context.secret().getBytes(StandardCharsets.UTF_8), context.rawBody()));
        return Hmac.constantTimeEquals(expected, provided.trim())
                ? VerificationResult.ok()
                : VerificationResult.fail(FailureReason.SIGNATURE_MISMATCH);
    }
}
