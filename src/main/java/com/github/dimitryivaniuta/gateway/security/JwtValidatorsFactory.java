package com.github.dimitryivaniuta.gateway.security;

import java.util.List;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;

/**
 * Factory for production-grade JWT validators.
 */
public final class JwtValidatorsFactory {

    private JwtValidatorsFactory() {}

    /**
     * Builds a composite validator:
     * <ul>
     *   <li>Default validators: exp/nbf etc</li>
     *   <li>Issuer exact match</li>
     *   <li>Audience contains expected</li>
     * </ul>
     */
    public static OAuth2TokenValidator<Jwt> issuerAndAudience(String issuer, String audience) {
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);

        OAuth2TokenValidator<Jwt> withAudience = (Jwt jwt) -> {
            List<String> aud = jwt.getAudience();
            if (aud != null && aud.contains(audience)) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token",
                    "Token audience (aud) does not contain expected audience: " + audience,
                    null
            ));
        };

        return withIssuer.and(withAudience);
    }
}
