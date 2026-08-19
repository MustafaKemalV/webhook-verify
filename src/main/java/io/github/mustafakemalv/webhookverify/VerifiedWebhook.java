package io.github.mustafakemalv.webhookverify;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a controller handler whose inbound webhook must have its signature verified before the
 * handler runs. The {@link #provider()} selects which verifier strategy is used. Works with both
 * the servlet and the reactive web layers.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface VerifiedWebhook {

    /** Provider id, e.g. "stripe", "github", "generic-hmac". */
    String provider();
}
