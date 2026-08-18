package io.github.mustafakemalv.webhookverify.web;

import io.github.mustafakemalv.webhookverify.core.FailureReason;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** Default failure handler: responds with 401 Unauthorized and nothing else. */
public class DefaultWebhookVerificationFailureHandler implements WebhookVerificationFailureHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            String provider, FailureReason reason) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
