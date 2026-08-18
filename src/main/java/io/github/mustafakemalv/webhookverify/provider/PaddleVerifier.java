package io.github.mustafakemalv.webhookverify.provider;

import io.github.mustafakemalv.webhookverify.core.FailureReason;
import io.github.mustafakemalv.webhookverify.core.Hmac;
import io.github.mustafakemalv.webhookverify.core.VerificationContext;
import io.github.mustafakemalv.webhookverify.core.VerificationResult;
import io.github.mustafakemalv.webhookverify.core.WebhookVerifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Paddle (Billing) webhook verifier. The {@code Paddle-Signature} header carries a timestamp and
 * one or more signatures: {@code ts=<unix>;h1=<hex>}. The signed payload is {@code <timestamp>:<rawBody>}
 * (concatenated as bytes, never re-serialized), keyed by the notification-destination secret with
 * HMAC-SHA256. The timestamp is checked against {@link VerificationContext#tolerance()} to reject replays.
 */
public final class PaddleVerifier implements WebhookVerifier {

    public static final String PROVIDER = "paddle";

    private static final String SIGNATURE_HEADER = "Paddle-Signature";
    private static final String TIMESTAMP_PREFIX = "ts";
    private static final String H1_SCHEME = "h1";

    @Override
    public String provider() {
        return PROVIDER;
    }

    @Override
    public VerificationResult verify(VerificationContext context) {
        String header = context.header(SIGNATURE_HEADER);
        if (header == null || header.isBlank()) {
            return VerificationResult.fail(FailureReason.MISSING_SIGNATURE);
        }

        Long timestamp = null;
        List<String> h1Signatures = new ArrayList<>();
        for (String element : header.split(";")) {
            String[] parts = element.trim().split("=", 2);
            if (parts.length != 2) {
                continue;
            }
            String key = parts[0].trim();
            String value = parts[1].trim();
            if (TIMESTAMP_PREFIX.equals(key)) {
                timestamp = parseEpochSeconds(value);
            } else if (H1_SCHEME.equals(key)) {
                h1Signatures.add(value);
            }
        }
        if (timestamp == null || h1Signatures.isEmpty()) {
            return VerificationResult.fail(FailureReason.MALFORMED_SIGNATURE);
        }

        long ageSeconds = context.now().getEpochSecond() - timestamp;
        if (ageSeconds > context.tolerance().toSeconds()) {
            return VerificationResult.fail(FailureReason.TIMESTAMP_OUT_OF_TOLERANCE);
        }

        byte[] signedPayload = signedPayload(timestamp, context.rawBody());
        String expected = Hmac.hex(
                Hmac.sha256(context.secret().getBytes(StandardCharsets.UTF_8), signedPayload));
        for (String candidate : h1Signatures) {
            if (Hmac.constantTimeEquals(expected, candidate)) {
                return VerificationResult.ok();
            }
        }
        return VerificationResult.fail(FailureReason.SIGNATURE_MISMATCH);
    }

    private static Long parseEpochSeconds(String value) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** Builds {@code <timestamp>:<rawBody>} at the byte level so the body is never re-encoded. */
    private static byte[] signedPayload(long timestamp, byte[] rawBody) {
        byte[] prefix = (timestamp + ":").getBytes(StandardCharsets.UTF_8);
        byte[] result = new byte[prefix.length + rawBody.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(rawBody, 0, result, prefix.length, rawBody.length);
        return result;
    }
}
