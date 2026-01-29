package com.github.dimitryivaniuta.gateway.demo;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import com.github.dimitryivaniuta.gateway.config.AuthProperties;

import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * Demo OIDC issuer endpoints embedded in the gateway, enabled only with {@code demo-issuer} profile.
 *
 * <p>This is for local testing and Postman: mint tokens, expose JWKS and a minimal OIDC discovery endpoint.</p>
 */
@Profile("demo-issuer")
@RestController
public class DemoIssuerController {

    private final DemoIssuerKeys keys;
    private final AuthProperties auth;

    public DemoIssuerController(DemoIssuerKeys keys, AuthProperties auth) {
        this.keys = keys;
        this.auth = auth;
    }

    @GetMapping("/.well-known/openid-configuration")
    public Map<String, Object> discovery() {
        return Map.of(
                "issuer", auth.getIssuer(),
                "jwks_uri", auth.getJwksUri()
        );
    }

    @GetMapping("/oauth2/jwks")
    public Map<String, Object> jwks() {
        return keys.jwkSet().toJSONObject();
    }

    /**
     * Rotates the demo issuer keys (adds a new current key while keeping previous keys).
     */
    @PostMapping("/api/demo/rotate")
    public ResponseEntity<?> rotate() {
        keys.rotate();
        return ResponseEntity.ok(Map.of("currentKid", keys.current().getKeyID(), "keys", keys.jwkSet().getKeys().size()));
    }

    /**
     * Mints a demo JWT signed by the current key.
     *
     * @param sub subject
     * @param roles comma-separated roles, e.g. USER,ADMIN
     * @param permissions comma-separated perms, e.g. orders:read,orders:write
     */
    @GetMapping("/api/demo/token")
    public Map<String, Object> token(
            @RequestParam(defaultValue = "john") String sub,
            @RequestParam(defaultValue = "USER") String roles,
            @RequestParam(defaultValue = "") String permissions
    ) throws Exception {

        RSAKey key = keys.current();
        Instant now = Instant.now();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(auth.getIssuer())
                .audience(auth.getAudience())
                .subject(sub)
                .issueTime(java.util.Date.from(now))
                .expirationTime(java.util.Date.from(now.plus(30, ChronoUnit.MINUTES)))
                .claim("roles", List.of(roles.split(",")))
                .claim("permissions", permissions.isBlank() ? List.of() : List.of(permissions.split(",")))
                .claim("scope", "api.read api.write")
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                claims
        );

        jwt.sign(new RSASSASigner(key.toPrivateKey()));

        return Map.of(
                "token", jwt.serialize(),
                "kid", key.getKeyID(),
                "expiresAt", claims.getExpirationTime().toInstant().toString()
        );
    }
}
