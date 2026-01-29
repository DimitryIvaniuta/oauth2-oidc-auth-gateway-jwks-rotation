package com.github.dimitryivaniuta.gateway.jwks;

import java.net.URI;
import java.time.Duration;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.JSONObjectUtils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Fetches JWKS from a remote JWKS URI.
 *
 * <p>Kept intentionally simple and robust: fetch JSON, parse to {@link JWKSet}.</p>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RemoteJwksFetcher {

    private final RestClient restClient = RestClient.create();

    public JWKSet fetch(URI jwksUri, Duration timeout) {
        try {
            String body = restClient.get()
                    .uri(jwksUri)
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .body(String.class);

            if (body == null || body.isBlank()) {
                throw new IllegalStateException("Empty JWKS response");
            }
            return JWKSet.parse(JSONObjectUtils.parse(body));
        } catch (Exception e) {
            log.error("Failed to fetch JWKS from {}: {}", jwksUri, e.getMessage());
            throw new IllegalStateException("Failed to fetch JWKS", e);
        }
    }
}
