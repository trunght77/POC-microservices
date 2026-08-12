package com.comicverse.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class GatewayOnlyFilter extends OncePerRequestFilter {

    private static final String GATEWAY_SECRET_HEADER = "X-Gateway-Secret";

    @Value("${GATEWAY_SHARED_SECRET:local-gateway-secret}")
    private String gatewaySharedSecret;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        if (isPublicEndpoint(request) || hasValidGatewaySecret(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"Requests must go through API Gateway\"}");
    }

    private boolean isPublicEndpoint(HttpServletRequest request) {
        return "/api/v1/health".equals(request.getRequestURI())
                || "/error".equals(request.getRequestURI());
    }

    private boolean hasValidGatewaySecret(HttpServletRequest request) {
        String requestSecret = request.getHeader(GATEWAY_SECRET_HEADER);
        return gatewaySharedSecret != null
                && !gatewaySharedSecret.isBlank()
                && gatewaySharedSecret.equals(requestSecret);
    }
}
