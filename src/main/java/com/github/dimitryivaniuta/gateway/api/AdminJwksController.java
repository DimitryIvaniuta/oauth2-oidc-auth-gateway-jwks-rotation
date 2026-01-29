package com.github.dimitryivaniuta.gateway.api;

import java.net.URI;
import java.time.Duration;

import com.github.dimitryivaniuta.gateway.config.AuthProperties;
import com.github.dimitryivaniuta.gateway.jwks.RemoteJwksFetcher;
import com.github.dimitryivaniuta.gateway.jwks.JwksCacheService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.JWKSet;

import lombok.RequiredArgsConstructor;

/**
 * Admin API to force a JWKS refresh (useful for incident response/ops).
 *
 * <p>In normal operation, refresh happens automatically on unknown {@code kid} and on schedule.</p>
 */
@RestController
@RequestMapping("/api/admin/jwks")
@RequiredArgsConstructor
public class AdminJwksController {

    private final AuthProperties authProperties;
    private final RemoteJwksFetcher fetcher;
    private final JwksCacheService cacheService;

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh() {
        URI uri = URI.create(authProperties.getJwksUri());
        JWKSet jwkSet = fetcher.fetch(uri, Duration.ofSeconds(2));
        cacheService.put(authProperties.getJwksCache().getRedisKey(), jwkSet, Math.max(30, authProperties.getJwksCache().getTtl().toSeconds()));
        return ResponseEntity.ok().body(java.util.Map.of(
                "keys", jwkSet.getKeys().size(),
                "redisKey", authProperties.getJwksCache().getRedisKey(),
                "jwksUri", authProperties.getJwksUri()
        ));
    }
}
