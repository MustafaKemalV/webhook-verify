package io.github.mustafakemalv.webhookverify.web;

import io.github.mustafakemalv.webhookverify.core.FailureReason;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Called when a webhook signature is missing or invalid, before the controller runs. The default
 * implementation sets 401; provide your own bean to log, emit metrics, or send a custom response.
 */
@FunctionalInterface
public interface WebhookVerificationFailureHandler {

    void handle(HttpServletRequest request, HttpServletResponse response,
            String provider, FailureReason reason) throws IOException;
}
