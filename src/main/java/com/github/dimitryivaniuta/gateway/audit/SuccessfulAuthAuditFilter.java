package com.github.dimitryivaniuta.gateway.audit;

import java.io.IOException;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * Creates an audit record for successful requests (valid JWT).
 *
 * <p>Failures are audited by the {@code AuthenticationEntryPoint} / {@code AccessDeniedHandler}.</p>
 */
@RequiredArgsConstructor
public class SuccessfulAuthAuditFilter extends OncePerRequestFilter {

    private final AuthAuditService auditService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        filterChain.doFilter(request, response);

        Object auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof JwtAuthenticationToken jat && jat.isAuthenticated()) {
            Jwt jwt = jat.getToken();
            // record only for API endpoints; skip actuator and issuer endpoints
            String path = request.getRequestURI();
            if (path.startsWith("/api/") && !path.startsWith("/api/demo/") && !path.startsWith("/api/admin/jwks/refresh")) {
                auditService.accepted(request, jwt);
            }
        }
    }
}
