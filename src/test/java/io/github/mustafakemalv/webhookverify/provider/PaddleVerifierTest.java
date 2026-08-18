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

class PaddleVerifierTest {

    private static final String HEADER = "Paddle-Signature";
    private static final String SECRET = "pdl_ntfset_secret";
    private static final Duration TOLERANCE = Duration.ofMinutes(5);
    private static final Instant NOW = Instant.ofEpochSecond(1_700_000_000L);

    private final PaddleVerifier verifier = new PaddleVerifier();

    private VerificationContext context(byte[] body, Map<String, String> headers) {
        return new VerificationContext(body, headers::get, SECRET, TOLERANCE, NOW);
    }

    private String h1(long ts, byte[] body) {
        byte[] prefix = (ts + ":").getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[prefix.length + body.length];
        System.arraycopy(prefix, 0, payload, 0, prefix.length);
        System.arraycopy(body, 0, payload, prefix.length, body.length);
        return Hmac.hex(Hmac.sha256(SECRET.getBytes(StandardCharsets.UTF_8), payload));
    }

    private String header(long ts, byte[] body) {
        return "ts=" + ts + ";h1=" + h1(ts, body);
    }

    @Test
    void accepts_a_valid_signature_within_tolerance() {
        byte[] body = "{\"event_type\":\"transaction.completed\"}".getBytes(StandardCharsets.UTF_8);
        VerificationResult result =
                verifier.verify(context(body, Map.of(HEADER, header(NOW.getEpochSecond(), body))));

        assertThat(result.valid()).isTrue();
    }

    @Test
    void rejects_a_missing_header() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        VerificationResult result = verifier.verify(context(body, Map.of()));

        assertThat(result.reason()).isEqualTo(FailureReason.MISSING_SIGNATURE);
    }

    @Test
    void rejects_a_header_without_ts_or_h1() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        VerificationResult result = verifier.verify(context(body, Map.of(HEADER, "h2=abc")));

        assertThat(result.reason()).isEqualTo(FailureReason.MALFORMED_SIGNATURE);
    }

    @Test
    void rejects_an_expired_timestamp() {
        byte[] body = "{\"event_type\":\"x\"}".getBytes(StandardCharsets.UTF_8);
        long tenMinutesAgo = NOW.getEpochSecond() - Duration.ofMinutes(10).toSeconds();

        VerificationResult result =
                verifier.verify(context(body, Map.of(HEADER, header(tenMinutesAgo, body))));

        assertThat(result.reason()).isEqualTo(FailureReason.TIMESTAMP_OUT_OF_TOLERANCE);
    }

    @Test
    void rejects_a_tampered_body() {
        byte[] original = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
        String header = header(NOW.getEpochSecond(), original);
        byte[] tampered = "{\"amount\":900}".getBytes(StandardCharsets.UTF_8);

        VerificationResult result = verifier.verify(context(tampered, Map.of(HEADER, header)));

        assertThat(result.reason()).isEqualTo(FailureReason.SIGNATURE_MISMATCH);
    }

    @Test
    void accepts_when_one_of_several_h1_signatures_matches() {
        byte[] body = "{\"event_type\":\"x\"}".getBytes(StandardCharsets.UTF_8);
        String header = "ts=" + NOW.getEpochSecond()
                + ";h1=deadbeef"
                + ";h1=" + h1(NOW.getEpochSecond(), body);

        VerificationResult result = verifier.verify(context(body, Map.of(HEADER, header)));

        assertThat(result.valid()).isTrue();
    }
}
