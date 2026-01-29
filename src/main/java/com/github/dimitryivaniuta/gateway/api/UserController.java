package com.github.dimitryivaniuta.gateway.api;

import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Example secured API.
 */
@RestController
@RequestMapping("/api/user")
public class UserController {

    @GetMapping("/me")
    public Map<String, Object> me(Authentication authentication) {
        JwtAuthenticationToken token = (JwtAuthenticationToken) authentication;
        Jwt jwt = token.getToken();

        return Map.of(
                "subject", jwt.getSubject(),
                "issuer", jwt.getIssuer() != null ? jwt.getIssuer().toString() : null,
                "audience", jwt.getAudience(),
                "issuedAt", jwt.getIssuedAt(),
                "expiresAt", jwt.getExpiresAt(),
                "claims", jwt.getClaims(),
                "authorities", token.getAuthorities().stream().map(a -> a.getAuthority()).collect(Collectors.toList())
        );
    }
}
