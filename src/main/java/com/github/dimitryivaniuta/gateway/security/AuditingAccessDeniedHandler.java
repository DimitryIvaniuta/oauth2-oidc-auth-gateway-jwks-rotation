package com.github.dimitryivaniuta.gateway.security;

import java.io.IOException;
import java.util.Optional;

import com.github.dimitryivaniuta.gateway.audit.AuthAuditService;

import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * Writes 403 and records an audit entry when authorization fails.
 */
@Component
@RequiredArgsConstructor
public class AuditingAccessDeniedHandler implements AccessDeniedHandler {

    private final AuthAuditService auditService;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
            throws IOException, ServletException {

        Authentication auth = (Authentication) request.getUserPrincipal();
        String subject = null;
        String kid = null;
        if (auth instanceof JwtAuthenticationToken jat) {
            subject = jat.getToken().getSubject();
            kid = Optional.ofNullable(jat.getToken().getHeaders().get("kid")).map(Object::toString).orElse(null);
        }

        auditService.forbidden(request, subject, kid, accessDeniedException.getMessage());

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{"error":"forbidden","message":"" + escape(accessDeniedException.getMessage()) + ""}");
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace(""", "\\"");
    }
}
