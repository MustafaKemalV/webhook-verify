package io.github.mustafakemalv.webhookverify.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class HmacTest {

    // Known test vector: HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog")
    private static final String KEY = "key";
    private static final String MESSAGE = "The quick brown fox jumps over the lazy dog";
    private static final String EXPECTED_HEX =
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";

    @Test
    void computes_known_hmac_sha256_vector() {
        byte[] mac = Hmac.sha256(KEY.getBytes(StandardCharsets.UTF_8),
                MESSAGE.getBytes(StandardCharsets.UTF_8));

        assertThat(Hmac.hex(mac)).isEqualTo(EXPECTED_HEX);
    }

    @Test
    void hex_is_lowercase_and_zero_padded() {
        assertThat(Hmac.hex(new byte[] {0x00, 0x0f, (byte) 0xff})).isEqualTo("000fff");
    }

    @Test
    void constant_time_equals_matches_identical_strings() {
        assertThat(Hmac.constantTimeEquals(EXPECTED_HEX, EXPECTED_HEX)).isTrue();
    }

    @Test
    void constant_time_equals_rejects_different_strings() {
        assertThat(Hmac.constantTimeEquals(EXPECTED_HEX, "deadbeef")).isFalse();
    }

    @Test
    void constant_time_equals_rejects_null() {
        assertThat(Hmac.constantTimeEquals(null, EXPECTED_HEX)).isFalse();
        assertThat(Hmac.constantTimeEquals(EXPECTED_HEX, null)).isFalse();
    }
}
