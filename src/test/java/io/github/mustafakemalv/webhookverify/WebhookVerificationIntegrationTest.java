package io.github.mustafakemalv.webhookverify;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.mustafakemalv.webhookverify.core.Hmac;
import io.github.mustafakemalv.webhookverify.web.VerifiedWebhook;
import io.github.mustafakemalv.webhookverify.web.WebhookVerificationFailureHandler;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@SpringBootTest(classes = WebhookVerificationIntegrationTest.TestApp.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "webhook-verify.providers.github.type=github",
        "webhook-verify.providers.github.secret=gh_secret",
        "webhook-verify.providers.stripe.type=stripe",
        "webhook-verify.providers.stripe.secret=whsec_test",
        "webhook-verify.providers.partner.type=generic-hmac",
        "webhook-verify.providers.partner.secret=gen_secret",
        "webhook-verify.providers.partner.signature-header=X-Sig",
        "webhook-verify.providers.paddle.type=paddle",
        "webhook-verify.providers.paddle.secret=pdl_secret",
        "webhook-verify.providers.shopify.type=generic-hmac",
        "webhook-verify.providers.shopify.secret=shpss_secret",
        "webhook-verify.providers.shopify.signature-header=X-Shopify-Hmac-Sha256",
        "webhook-verify.providers.shopify.encoding=base64"
})
class WebhookVerificationIntegrationTest {

    private static final long NOW_EPOCH = 1_700_000_000L;

    @Autowired
    private MockMvc mockMvc;

    // --- signing helpers (mirror what each provider expects) ---

    private static String hex(String secret, byte[] message) {
        return Hmac.hex(Hmac.sha256(secret.getBytes(StandardCharsets.UTF_8), message));
    }

    private static String base64(String secret, byte[] message) {
        return Base64.getEncoder().encodeToString(
                Hmac.sha256(secret.getBytes(StandardCharsets.UTF_8), message));
    }

    private static String stripeV1(long ts, byte[] body, String secret) {
        return hex(secret, timestamped(ts, ".", body));
    }

    private static String paddleH1(long ts, byte[] body, String secret) {
        return hex(secret, timestamped(ts, ":", body));
    }

    private static byte[] timestamped(long ts, String separator, byte[] body) {
        byte[] prefix = (ts + separator).getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[prefix.length + body.length];
        System.arraycopy(prefix, 0, payload, 0, prefix.length);
        System.arraycopy(body, 0, payload, prefix.length, body.length);
        return payload;
    }

    // --- GitHub ---

    @Test
    void github_valid_signature_passes_and_controller_sees_raw_body() throws Exception {
        byte[] body = "{\"action\":\"opened\"}".getBytes(StandardCharsets.UTF_8);

        mockMvc.perform(post("/webhooks/github")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body)
                        .header("X-Hub-Signature-256", "sha256=" + hex("gh_secret", body)))
                .andExpect(status().isOk())
                .andExpect(content().string("ok:" + new String(body, StandardCharsets.UTF_8)));
    }

    @Test
    void github_tampered_body_is_rejected() throws Exception {
        byte[] signed = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
        byte[] tampered = "{\"amount\":900}".getBytes(StandardCharsets.UTF_8);

        mockMvc.perform(post("/webhooks/github")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(tampered)
                        .header("X-Hub-Signature-256", "sha256=" + hex("gh_secret", signed)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void github_missing_signature_is_rejected() throws Exception {
        mockMvc.perform(post("/webhooks/github")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}".getBytes(StandardCharsets.UTF_8)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void custom_failure_handler_adds_error_header() throws Exception {
        mockMvc.perform(post("/webhooks/github")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}".getBytes(StandardCharsets.UTF_8)))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("X-Webhook-Error", "github:MISSING_SIGNATURE"));
    }

    // --- Stripe ---

    @Test
    void stripe_valid_signature_within_tolerance_passes() throws Exception {
        byte[] body = "{\"id\":\"evt_1\"}".getBytes(StandardCharsets.UTF_8);
        String header = "t=" + NOW_EPOCH + ",v1=" + stripeV1(NOW_EPOCH, body, "whsec_test");

        mockMvc.perform(post("/webhooks/stripe")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body)
                        .header("Stripe-Signature", header))
                .andExpect(status().isOk());
    }

    @Test
    void stripe_expired_timestamp_is_rejected() throws Exception {
        byte[] body = "{\"id\":\"evt_1\"}".getBytes(StandardCharsets.UTF_8);
        long sixMinutesAgo = NOW_EPOCH - 360;
        String header = "t=" + sixMinutesAgo + ",v1=" + stripeV1(sixMinutesAgo, body, "whsec_test");

        mockMvc.perform(post("/webhooks/stripe")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body)
                        .header("Stripe-Signature", header))
                .andExpect(status().isUnauthorized());
    }

    // --- Paddle ---

    @Test
    void paddle_valid_signature_within_tolerance_passes() throws Exception {
        byte[] body = "{\"event_type\":\"transaction.completed\"}".getBytes(StandardCharsets.UTF_8);
        String header = "ts=" + NOW_EPOCH + ";h1=" + paddleH1(NOW_EPOCH, body, "pdl_secret");

        mockMvc.perform(post("/webhooks/paddle")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body)
                        .header("Paddle-Signature", header))
                .andExpect(status().isOk());
    }

    @Test
    void paddle_expired_timestamp_is_rejected() throws Exception {
        byte[] body = "{\"event_type\":\"x\"}".getBytes(StandardCharsets.UTF_8);
        long tenMinutesAgo = NOW_EPOCH - 600;
        String header = "ts=" + tenMinutesAgo + ";h1=" + paddleH1(tenMinutesAgo, body, "pdl_secret");

        mockMvc.perform(post("/webhooks/paddle")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body)
                        .header("Paddle-Signature", header))
                .andExpect(status().isUnauthorized());
    }

    // --- Generic (hex) ---

    @Test
    void generic_valid_signature_passes() throws Exception {
        byte[] body = "{\"ping\":true}".getBytes(StandardCharsets.UTF_8);

        mockMvc.perform(post("/webhooks/partner")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body)
                        .header("X-Sig", hex("gen_secret", body)))
                .andExpect(status().isOk());
    }

    // --- Generic (base64, Shopify-style) ---

    @Test
    void shopify_valid_base64_signature_passes() throws Exception {
        byte[] body = "{\"id\":123}".getBytes(StandardCharsets.UTF_8);

        mockMvc.perform(post("/webhooks/shopify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body)
                        .header("X-Shopify-Hmac-Sha256", base64("shpss_secret", body)))
                .andExpect(status().isOk());
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class TestApp {

        @Bean
        Clock fixedClock() {
            return Clock.fixed(Instant.ofEpochSecond(NOW_EPOCH), ZoneOffset.UTC);
        }

        @Bean
        WebhookVerificationFailureHandler failureHandler() {
            return (req, res, provider, reason) -> {
                res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                res.setHeader("X-Webhook-Error", provider + ":" + reason);
            };
        }

        @RestController
        static class WebhookController {

            @PostMapping("/webhooks/github")
            @VerifiedWebhook(provider = "github")
            String github(@RequestBody String body) {
                return "ok:" + body;
            }

            @PostMapping("/webhooks/stripe")
            @VerifiedWebhook(provider = "stripe")
            String stripe(@RequestBody String body) {
                return "ok:" + body;
            }

            @PostMapping("/webhooks/paddle")
            @VerifiedWebhook(provider = "paddle")
            String paddle(@RequestBody String body) {
                return "ok:" + body;
            }

            @PostMapping("/webhooks/partner")
            @VerifiedWebhook(provider = "partner")
            String partner(@RequestBody String body) {
                return "ok:" + body;
            }

            @PostMapping("/webhooks/shopify")
            @VerifiedWebhook(provider = "shopify")
            String shopify(@RequestBody String body) {
                return "ok:" + body;
            }
        }
    }
}
