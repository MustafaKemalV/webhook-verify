package io.github.mustafakemalv.webhookverify.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.mustafakemalv.webhookverify.autoconfigure.WebhookVerifyProperties;
import io.github.mustafakemalv.webhookverify.core.FailureReason;
import io.github.mustafakemalv.webhookverify.core.Hmac;
import io.github.mustafakemalv.webhookverify.core.WebhookVerifier;
import io.github.mustafakemalv.webhookverify.observability.WebhookVerificationMetrics;
import io.github.mustafakemalv.webhookverify.provider.GenericHmacVerifier;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;

class WebhookVerificationInterceptorTest {

    private static final String PROVIDER = "partner";
    private static final String HEADER = "X-Signature";
    private static final String SECRET = "s3cr3t";

    private final WebhookVerificationInterceptor interceptor =
            interceptor(new DefaultWebhookVerificationFailureHandler());

    private WebhookVerifyProperties properties() {
        WebhookVerifyProperties properties = new WebhookVerifyProperties();
        WebhookVerifyProperties.Provider provider = new WebhookVerifyProperties.Provider();
        provider.setType("generic-hmac");
        provider.setSecret(SECRET);
        provider.setSignatureHeader(HEADER);
        properties.getProviders().put(PROVIDER, provider);
        return properties;
    }

    private WebhookVerificationInterceptor interceptor(WebhookVerificationFailureHandler failureHandler) {
        Map<String, WebhookVerifier> verifiers = Map.of(PROVIDER, new GenericHmacVerifier(HEADER));
        return new WebhookVerificationInterceptor(verifiers, properties(), Clock.systemUTC(),
                failureHandler, WebhookVerificationMetrics.NO_OP);
    }

    static class TestController {
        @VerifiedWebhook(provider = PROVIDER)
        public void secured() {
        }

        public void open() {
        }
    }

    private HandlerMethod handler(String method) throws NoSuchMethodException {
        return new HandlerMethod(new TestController(), TestController.class.getMethod(method));
    }

    private CachedBodyHttpServletRequest request(byte[] body, String signature) throws Exception {
        MockHttpServletRequest raw = new MockHttpServletRequest("POST", "/webhooks/partner");
        raw.setContent(body);
        if (signature != null) {
            raw.addHeader(HEADER, signature);
        }
        return new CachedBodyHttpServletRequest(raw);
    }

    private String sign(byte[] body) {
        return Hmac.hex(Hmac.sha256(SECRET.getBytes(StandardCharsets.UTF_8), body));
    }

    @Test
    void lets_unannotated_handlers_through() throws Exception {
        boolean proceed = interceptor.preHandle(
                request("{}".getBytes(StandardCharsets.UTF_8), null),
                new MockHttpServletResponse(),
                handler("open"));

        assertThat(proceed).isTrue();
    }

    @Test
    void allows_a_valid_signature() throws Exception {
        byte[] body = "{\"event\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
        MockHttpServletResponse response = new MockHttpServletResponse();

        boolean proceed = interceptor.preHandle(request(body, sign(body)), response, handler("secured"));

        assertThat(proceed).isTrue();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    void rejects_an_invalid_signature_with_401() throws Exception {
        byte[] body = "{\"event\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
        MockHttpServletResponse response = new MockHttpServletResponse();

        boolean proceed = interceptor.preHandle(request(body, "deadbeef"), response, handler("secured"));

        assertThat(proceed).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    void invokes_custom_failure_handler_with_provider_and_reason() throws Exception {
        AtomicReference<String> capturedProvider = new AtomicReference<>();
        AtomicReference<FailureReason> capturedReason = new AtomicReference<>();
        WebhookVerificationFailureHandler custom = (req, res, provider, reason) -> {
            capturedProvider.set(provider);
            capturedReason.set(reason);
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
        };
        WebhookVerificationInterceptor customInterceptor = interceptor(custom);
        byte[] body = "{\"event\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
        MockHttpServletResponse response = new MockHttpServletResponse();

        boolean proceed = customInterceptor.preHandle(request(body, "deadbeef"), response, handler("secured"));

        assertThat(proceed).isFalse();
        assertThat(capturedProvider.get()).isEqualTo(PROVIDER);
        assertThat(capturedReason.get()).isEqualTo(FailureReason.SIGNATURE_MISMATCH);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }
}
