package com.github.dimitryivaniuta.gateway.jwks;

import java.time.Instant;

import com.nimbusds.jose.jwk.JWKSet;

import lombok.Value;

/**
 * Holds a JWKS with an expiration timestamp (local in-memory cache).
 */
@Value
public class CachedJwkSet {
    JWKSet jwkSet;
    Instant expiresAt;

    public boolean isExpired(Instant now) {
        return now.isAfter(expiresAt);
    }
}
