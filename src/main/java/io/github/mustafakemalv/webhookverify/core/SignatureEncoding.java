package io.github.mustafakemalv.webhookverify.core;

import java.util.Base64;

/** How a provider encodes the HMAC bytes into the signature string. */
public enum SignatureEncoding {

    HEX {
        @Override
        public String encode(byte[] bytes) {
            return Hmac.hex(bytes);
        }
    },
    BASE64 {
        @Override
        public String encode(byte[] bytes) {
            return Base64.getEncoder().encodeToString(bytes);
        }
    };

    /** Encodes raw HMAC bytes into the string form a provider sends. */
    public abstract String encode(byte[] bytes);
}
