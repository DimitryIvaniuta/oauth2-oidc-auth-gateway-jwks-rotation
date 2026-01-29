package com.github.dimitryivaniuta.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the OAuth2/OIDC Auth Gateway.
 *
 * <p>This service validates incoming JWT Bearer tokens using a remote JWKS endpoint.
 * JWKS is cached in Redis (shared across instances) and in local memory, supporting seamless key rotation.</p>
 */
@SpringBootApplication
public class AuthGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthGatewayApplication.class, args);
    }
}
