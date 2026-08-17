package io.github.mustafakemalv.webhookverify.core;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC-SHA256 primitives shared by all providers: signature computation, lowercase
 * hex encoding, and a constant-time comparison that does not leak how many leading
 * bytes matched (defence against timing attacks).
 */
public final class Hmac {

    private static final String HMAC_SHA256 = "HmacSHA256";

    private Hmac() {
    }

    /** Computes HMAC-SHA256 of {@code message} keyed by {@code key}. */
    public static byte[] sha256(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(key, HMAC_SHA256));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is not available on this JVM", e);
        }
    }

    /** Lowercase hex encoding of {@code bytes}. */
    public static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    /**
     * Constant-time comparison of two signatures. Returns false on any null and never
     * short-circuits on the first differing byte, so timing does not reveal the secret.
     */
    public static boolean constantTimeEquals(String expected, String actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }
}
