package io.github.mustafakemalv.webhookverify.core;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;

/**
 * Everything a {@link WebhookVerifier} needs, decoupled from the servlet API for
 * testability: the raw request bytes (never re-serialized), a case-insensitive header
 * lookup, the shared secret, the replay tolerance and the current instant (injectable
 * so timestamp/replay tests stay deterministic).
 */
public record VerificationContext(
        byte[] rawBody,
        Function<String, String> headerLookup,
        String secret,
        Duration tolerance,
        Instant now) {

    /** Convenience header lookup; returns null when the header is absent. */
    public String header(String name) {
        return headerLookup.apply(name);
    }
}
