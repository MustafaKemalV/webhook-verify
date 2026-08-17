/**
 * webhook-verify: a Spring Boot starter that verifies inbound webhook signatures
 * for multiple providers (Stripe, GitHub, generic HMAC) before the request body
 * is parsed, using a {@code @VerifiedWebhook} annotation and a raw-body-capturing
 * servlet filter.
 */
package io.github.mustafakemalv.webhookverify;
