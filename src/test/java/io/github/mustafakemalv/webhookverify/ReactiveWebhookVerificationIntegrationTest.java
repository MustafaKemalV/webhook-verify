package io.github.mustafakemalv.webhookverify;

import io.github.mustafakemalv.webhookverify.core.Hmac;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@SpringBootTest(classes = ReactiveWebhookVerificationIntegrationTest.ReactiveTestApp.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.main.web-application-type=reactive")
@AutoConfigureWebTestClient
@TestPropertySource(properties = {
        "webhook-verify.providers.github.type=github",
        "webhook-verify.providers.github.secret=gh_secret"
})
class ReactiveWebhookVerificationIntegrationTest {

    @Autowired
    private WebTestClient webTestClient;

    private static String hex(String secret, byte[] message) {
        return Hmac.hex(Hmac.sha256(secret.getBytes(StandardCharsets.UTF_8), message));
    }

    @Test
    void github_valid_signature_passes_and_controller_sees_raw_body() {
        byte[] body = "{\"action\":\"opened\"}".getBytes(StandardCharsets.UTF_8);
        webTestClient.post().uri("/webhooks/github")
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Hub-Signature-256", "sha256=" + hex("gh_secret", body))
                .bodyValue(new String(body, StandardCharsets.UTF_8))
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("ok:" + new String(body, StandardCharsets.UTF_8));
    }

    @Test
    void github_tampered_body_is_rejected() {
        byte[] signed = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
        byte[] tampered = "{\"amount\":900}".getBytes(StandardCharsets.UTF_8);
        webTestClient.post().uri("/webhooks/github")
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Hub-Signature-256", "sha256=" + hex("gh_secret", signed))
                .bodyValue(new String(tampered, StandardCharsets.UTF_8))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void github_missing_signature_is_rejected() {
        webTestClient.post().uri("/webhooks/github")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class ReactiveTestApp {

        @RestController
        static class WebhookController {

            @PostMapping("/webhooks/github")
            @VerifiedWebhook(provider = "github")
            Mono<String> github(@RequestBody String body) {
                return Mono.just("ok:" + body);
            }
        }
    }
}
