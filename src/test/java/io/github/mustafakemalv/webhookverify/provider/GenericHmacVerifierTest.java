package io.github.mustafakemalv.webhookverify.provider;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.mustafakemalv.webhookverify.core.FailureReason;
import io.github.mustafakemalv.webhookverify.core.Hmac;
import io.github.mustafakemalv.webhookverify.core.SignatureEncoding;
import io.github.mustafakemalv.webhookverify.core.VerificationContext;
import io.github.mustafakemalv.webhookverify.core.VerificationResult;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;

class GenericHmacVerifierTest {

    private static final String SECRET = "topsecret";
    private static final String HEADER = "X-Signature";
    private final GenericHmacVerifier verifier = new GenericHmacVerifier(HEADER);

    private VerificationContext context(byte[] body, Map<String, String> headers) {
        return new VerificationContext(body, headers::get, SECRET,
                Duration.ofMinutes(5), Instant.now());
    }

    private String sign(byte[] body) {
        return Hmac.hex(Hmac.sha256(SECRET.getBytes(StandardCharsets.UTF_8), body));
    }

    @Test
    void accepts_a_valid_signature() {
        byte[] body = "{\"event\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
        VerificationResult result = verifier.verify(context(body, Map.of(HEADER, sign(body))));

        assertThat(result.valid()).isTrue();
    }

    @Test
    void rejects_a_missing_signature() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        VerificationResult result = verifier.verify(context(body, Map.of()));

        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.MISSING_SIGNATURE);
    }

    @Test
    void rejects_a_wrong_signature() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        VerificationResult result = verifier.verify(context(body, Map.of(HEADER, "deadbeef")));

        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.SIGNATURE_MISMATCH);
    }

    @Test
    void rejects_a_single_byte_tamper() {
        byte[] original = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
        String signature = sign(original);
        byte[] tampered = "{\"amount\":900}".getBytes(StandardCharsets.UTF_8);

        VerificationResult result = verifier.verify(context(tampered, Map.of(HEADER, signature)));

        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.SIGNATURE_MISMATCH);
    }

    @Test
    void accepts_a_valid_base64_signature() {
        GenericHmacVerifier base64Verifier = new GenericHmacVerifier(HEADER, SignatureEncoding.BASE64);
        byte[] body = "{\"event\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
        String signature = Base64.getEncoder().encodeToString(
                Hmac.sha256(SECRET.getBytes(StandardCharsets.UTF_8), body));

        VerificationResult result = base64Verifier.verify(context(body, Map.of(HEADER, signature)));

        assertThat(result.valid()).isTrue();
    }
}
