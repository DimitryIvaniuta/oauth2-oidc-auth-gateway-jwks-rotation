package com.github.dimitryivaniuta.gateway.jwks;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.JSONObjectUtils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Redis-backed JWKS cache.
 *
 * <p>We store serialized JWKS JSON under a single Redis key to share cache across instances.
 * TTL is managed by Redis and mirrored in-memory for fast access.</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JwksCacheService {

    private final StringRedisTemplate redis;
    private final Clock clock = Clock.systemUTC();

    /**
     * Reads JWKS JSON from Redis (if present) and parses it.
     *
     * @param redisKey cache key
     * @return optional JWKSet
     */
    public Optional<JWKSet> get(String redisKey) {
        String json = redis.opsForValue().get(redisKey);
        if (json == null || json.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(JWKSet.parse(JSONObjectUtils.parse(json)));
        } catch (Exception e) {
            log.warn("Failed to parse cached JWKS from Redis key={}: {}", redisKey, e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Writes JWKS JSON to Redis with TTL.
     *
     * @param redisKey cache key
     * @param jwkSet parsed set
     * @param ttlSeconds TTL in seconds
     */
    public void put(String redisKey, JWKSet jwkSet, long ttlSeconds) {
        try {
            String json = JSONObjectUtils.toJSONString(jwkSet.toJSONObject(true));
            redis.opsForValue().set(redisKey, json, java.time.Duration.ofSeconds(ttlSeconds));
        } catch (Exception e) {
            log.warn("Failed to cache JWKS to Redis key={}: {}", redisKey, e.getMessage());
        }
    }

    public Instant now() {
        return clock.instant();
    }
}
