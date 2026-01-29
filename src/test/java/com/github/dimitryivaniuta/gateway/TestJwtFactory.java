package com.github.dimitryivaniuta.gateway;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * Helper for creating signed JWTs in tests.
 */
public final class TestJwtFactory {

    private TestJwtFactory() {}

    public static String mint(RSAKey signingKey, String issuer, String audience, String sub, Instant now, List<String> roles) {
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .audience(audience)
                    .subject(sub)
                    .issueTime(java.util.Date.from(now))
                    .expirationTime(java.util.Date.from(now.plus(10, ChronoUnit.MINUTES)))
                    .claim("roles", roles)
                    .claim("scope", "api.read")
                    .build();

            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(),
                    claims
            );

            jwt.sign(new RSASSASigner(signingKey.toPrivateKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
