package com.github.dimitryivaniuta.gateway.security;

import java.io.IOException;

import com.github.dimitryivaniuta.gateway.audit.AuthAuditService;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * Writes 401 and records an audit entry when authentication fails.
 */
@Component
@RequiredArgsConstructor
public class AuditingAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final AuthAuditService auditService;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {

        auditService.rejected(request, authException.getMessage());

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{"error":"unauthorized","message":"" + escape(authException.getMessage()) + ""}");
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace(""", "\\"");
    }
}
