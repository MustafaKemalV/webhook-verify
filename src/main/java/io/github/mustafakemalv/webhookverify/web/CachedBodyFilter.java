package io.github.mustafakemalv.webhookverify.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Wraps requests that can carry a body (POST/PUT/PATCH) in a {@link CachedBodyHttpServletRequest}
 * so the raw body survives being read by the signature check and again by the controller.
 */
public final class CachedBodyFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        if (hasBody(request)) {
            filterChain.doFilter(new CachedBodyHttpServletRequest(request), response);
        } else {
            filterChain.doFilter(request, response);
        }
    }

    private static boolean hasBody(HttpServletRequest request) {
        String method = request.getMethod();
        return "POST".equalsIgnoreCase(method)
                || "PUT".equalsIgnoreCase(method)
                || "PATCH".equalsIgnoreCase(method);
    }
}
