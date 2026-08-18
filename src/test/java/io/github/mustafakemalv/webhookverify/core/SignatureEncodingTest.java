package io.github.mustafakemalv.webhookverify.core;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SignatureEncodingTest {

    private static final byte[] SAMPLE = {0x00, 0x0f, (byte) 0xff};

    @Test
    void hex_encodes_lowercase() {
        assertThat(SignatureEncoding.HEX.encode(SAMPLE)).isEqualTo("000fff");
    }

    @Test
    void base64_encodes_standard() {
        assertThat(SignatureEncoding.BASE64.encode(SAMPLE)).isEqualTo("AA//");
    }
}
