package com.github.dimitryivaniuta.gateway.jwks;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import org.springframework.stereotype.Component;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.selector.JWKSelector;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Nimbus {@link JWKSource} that:
 * <ul>
 *   <li>Loads JWKS from local in-memory cache</li>
 *   <li>Falls back to Redis shared cache</li>
 *   <li>Fetches from remote JWKS URI if missing/expired</li>
 *   <li>Forces refresh when a token uses an unknown {@code kid}</li>
 * </ul>
 *
 * <p>This design supports key rotation with no downtime: when a new key appears, the selector misses,
 * so we re-fetch JWKS and re-select keys.</p>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RedisCachingJwkSource implements JWKSource<SecurityContext> {

    private final JwksCacheService cacheService;
    private final RemoteJwksFetcher remoteFetcher;

    private final AtomicReference<CachedJwkSet> local = new AtomicReference<>();

    // populated by configuration
    private volatile URI jwksUri;
    private volatile String redisKey;
    private volatile Duration ttl;
    private volatile Duration httpTimeout;

    public void configure(URI jwksUri, String redisKey, Duration ttl, Duration httpTimeout) {
        this.jwksUri = Objects.requireNonNull(jwksUri, "jwksUri");
        this.redisKey = Objects.requireNonNull(redisKey, "redisKey");
        this.ttl = Objects.requireNonNull(ttl, "ttl");
        this.httpTimeout = Objects.requireNonNullElse(httpTimeout, Duration.ofSeconds(2));
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
        try {
            JWKSet jwkSet = loadOrRefresh(false);
            List<JWK> selected = jwkSelector.select(jwkSet);
            if (!selected.isEmpty()) {
                return selected;
            }

            // If selector finds nothing, most common reason is rotation: unknown kid.
            // Force refresh and try again.
            jwkSet = loadOrRefresh(true);
            selected = jwkSelector.select(jwkSet);
            return selected;
        } catch (Exception e) {
            throw new KeySourceException("Unable to obtain keys from JWKS", e);
        }
    }

    private JWKSet loadOrRefresh(boolean force) {
        Instant now = cacheService.now();
        CachedJwkSet cached = local.get();

        if (!force && cached != null && !cached.isExpired(now)) {
            return cached.getJwkSet();
        }

        if (!force) {
            // try redis
            JWKSet fromRedis = cacheService.get(redisKey).orElse(null);
            if (fromRedis != null) {
                local.set(new CachedJwkSet(fromRedis, now.plus(ttl)));
                return fromRedis;
            }
        }

        // fetch remote
        if (jwksUri == null) {
            throw new IllegalStateException("RedisCachingJwkSource not configured with jwksUri");
        }
        JWKSet fetched = remoteFetcher.fetch(jwksUri, httpTimeout);

        long ttlSeconds = Math.max(30, ttl.toSeconds());
        cacheService.put(redisKey, fetched, ttlSeconds);
        local.set(new CachedJwkSet(fetched, now.plusSeconds(ttlSeconds)));

        log.info("JWKS refreshed (force={}): keys={}", force, fetched.getKeys().size());
        return fetched;
    }
}
