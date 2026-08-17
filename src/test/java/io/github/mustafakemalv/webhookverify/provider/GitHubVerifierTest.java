package io.github.mustafakemalv.webhookverify.provider;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.mustafakemalv.webhookverify.core.FailureReason;
import io.github.mustafakemalv.webhookverify.core.Hmac;
import io.github.mustafakemalv.webhookverify.core.VerificationContext;
import io.github.mustafakemalv.webhookverify.core.VerificationResult;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

class GitHubVerifierTest {

    private static final String HEADER = "X-Hub-Signature-256";
    private final GitHubVerifier verifier = new GitHubVerifier();

    private VerificationContext context(byte[] body, String secret, Map<String, String> headers) {
        return new VerificationContext(body, headers::get, secret, Duration.ofMinutes(5), Instant.now());
    }

    @Test
    void accepts_the_signature_from_github_documentation() {
        // Exact example from GitHub's "Validating webhook deliveries" docs.
        String secret = "It's a Secret to Everybody";
        byte[] body = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        String signature = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

        VerificationResult result = verifier.verify(context(body, secret, Map.of(HEADER, signature)));

        assertThat(result.valid()).isTrue();
    }

    @Test
    void rejects_a_missing_signature() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        VerificationResult result = verifier.verify(context(body, "secret", Map.of()));

        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.MISSING_SIGNATURE);
    }

    @Test
    void rejects_a_signature_without_the_sha256_prefix() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        String secret = "secret";
        String hexOnly = Hmac.hex(Hmac.sha256(secret.getBytes(StandardCharsets.UTF_8), body));

        VerificationResult result = verifier.verify(context(body, secret, Map.of(HEADER, hexOnly)));

        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.MALFORMED_SIGNATURE);
    }

    @Test
    void rejects_a_wrong_signature() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        VerificationResult result =
                verifier.verify(context(body, "secret", Map.of(HEADER, "sha256=deadbeef")));

        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.SIGNATURE_MISMATCH);
    }

    @Test
    void rejects_a_single_byte_tamper() {
        String secret = "secret";
        byte[] original = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
        String signature = "sha256=" + Hmac.hex(Hmac.sha256(secret.getBytes(StandardCharsets.UTF_8), original));
        byte[] tampered = "{\"amount\":900}".getBytes(StandardCharsets.UTF_8);

        VerificationResult result = verifier.verify(context(tampered, secret, Map.of(HEADER, signature)));

        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.SIGNATURE_MISMATCH);
    }
}
