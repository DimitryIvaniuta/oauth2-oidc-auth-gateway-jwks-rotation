package com.github.dimitryivaniuta.gateway.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

/**
 * Configuration for JWT validation and JWKS caching.
 */
@Data
@Validated
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    /**
     * Expected issuer (iss) claim. Must match exactly.
     */
    @NotBlank
    private String issuer;

    /**
     * Expected audience (aud) claim. Token must contain it.
     */
    @NotBlank
    private String audience;

    /**
     * Remote JWKS URI (JSON Web Key Set).
     */
    @NotBlank
    private String jwksUri;

    /**
     * JWKS cache settings (Redis + local memory).
     */
    @NotNull
    private JwksCache jwksCache = new JwksCache();

    @Data
    public static class JwksCache {
        /**
         * Redis key where the serialized JWKS JSON is stored.
         */
        @NotBlank
        private String redisKey = "auth-gateway:jwks";

        /**
         * Time-to-live for cached JWKS in Redis and memory.
         */
        @NotNull
        private Duration ttl = Duration.ofMinutes(10);

        /**
         * Background refresh delay in milliseconds.
         *
         * <p>Even though unknown {@code kid} triggers refresh, this periodic refresh
         * reduces reliance on stale caches across instances.</p>
         */
        private long refreshDelayMillis = 300_000;
    }
}
