package com.github.dimitryivaniuta.gateway.jwks;

import java.net.URI;
import java.time.Duration;

import com.github.dimitryivaniuta.gateway.config.AuthProperties;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.jwk.JWKSet;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Periodic JWKS refresh.
 *
 * <p>Even though unknown {@code kid} triggers a refresh, a scheduled refresh reduces the window
 * where instances might rely on an older cache entry.</p>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwksRefresher {

    private final AuthProperties authProperties;
    private final RemoteJwksFetcher fetcher;
    private final JwksCacheService cacheService;

    @Scheduled(fixedDelayString = "${auth.jwksCache.refreshDelayMillis:300000}")
    public void refresh() {
        try {
            URI uri = URI.create(authProperties.getJwksUri());
            JWKSet jwkSet = fetcher.fetch(uri, Duration.ofSeconds(2));
            cacheService.put(
                    authProperties.getJwksCache().getRedisKey(),
                    jwkSet,
                    Math.max(30, authProperties.getJwksCache().getTtl().toSeconds())
            );
            log.debug("Scheduled JWKS refresh: keys={}", jwkSet.getKeys().size());
        } catch (Exception e) {
            log.warn("Scheduled JWKS refresh failed: {}", e.getMessage());
        }
    }
}
