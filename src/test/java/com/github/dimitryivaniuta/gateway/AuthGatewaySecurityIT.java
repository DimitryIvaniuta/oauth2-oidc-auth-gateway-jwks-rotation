package com.github.dimitryivaniuta.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import com.github.dimitryivaniuta.gateway.audit.AuthAuditRepository;
import com.github.dimitryivaniuta.gateway.containers.Containers;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.kafka.test.context.EmbeddedKafka;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

/**
 * Integration tests:
 * - validates JWT via JWKS
 * - supports JWKS rotation (new kid works immediately)
 * - stores audit records
 */
@SpringBootTest
@AutoConfigureMockMvc
@EmbeddedKafka(partitions = 1, topics = { "auth-audit-events" })
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthGatewaySecurityIT {

    private static final WireMockServer WIREMOCK = new WireMockServer(0);

    private static RSAKey key1;
    private static RSAKey key2;

    @Autowired MockMvc mvc;
    @Autowired AuthAuditRepository auditRepository;

    private static String redisKey;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        if (!WIREMOCK.isRunning()) {
            WIREMOCK.start();
        }
        redisKey = "test:jwks:" + UUID.randomUUID();

        r.add("spring.datasource.url", () -> Containers.POSTGRES.getJdbcUrl());
        r.add("spring.datasource.username", () -> Containers.POSTGRES.getUsername());
        r.add("spring.datasource.password", () -> Containers.POSTGRES.getPassword());

        r.add("spring.data.redis.host", () -> Containers.REDIS.getHost());
        r.add("spring.data.redis.port", () -> Containers.REDIS.getMappedPort(6379));

        r.add("spring.kafka.bootstrap-servers", () -> System.getProperty("spring.embedded.kafka.brokers"));

        r.add("auth.issuer", () -> "http://issuer.test");
        r.add("auth.audience", () -> "api");
        r.add("auth.jwksUri", () -> "http://localhost:" + WIREMOCK.port() + "/jwks");
        r.add("auth.jwksCache.redisKey", () -> redisKey);
        r.add("auth.jwksCache.ttl", () -> "PT2M");
        r.add("auth.jwksCache.refreshDelayMillis", () -> "30000");
    }

    @BeforeAll
    void setup() throws Exception {
        key1 = newKey("kid-1");
        key2 = newKey("kid-2");
        stubJwks(new JWKSet(List.of(key1.toPublicJWK())));
    }

    @AfterAll
    void teardown() {
        if (WIREMOCK.isRunning()) WIREMOCK.stop();
    }

    @Test
    void accepts_valid_token_and_writes_audit() throws Exception {
        String jwt = TestJwtFactory.mint(key1, "http://issuer.test", "api", "john", Instant.now(), List.of("USER"));

        mvc.perform(get("/api/user/me")
                .header("Authorization", "Bearer " + jwt))
                .andExpect(status().isOk());

        assertThat(auditRepository.count()).isGreaterThan(0);
    }

    @Test
    void rejects_wrong_audience() throws Exception {
        String jwt = TestJwtFactory.mint(key1, "http://issuer.test", "WRONG", "john", Instant.now(), List.of("USER"));

        mvc.perform(get("/api/user/me")
                .header("Authorization", "Bearer " + jwt))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void supports_jwks_rotation_new_kid_works_immediately() throws Exception {
        stubJwks(new JWKSet(List.of(key2.toPublicJWK())));

        String jwt = TestJwtFactory.mint(key2, "http://issuer.test", "api", "alice", Instant.now(), List.of("ADMIN"));

        mvc.perform(get("/api/user/me")
                .header("Authorization", "Bearer " + jwt))
                .andExpect(status().isOk());
    }

    private static void stubJwks(JWKSet jwkSet) {
        WIREMOCK.resetMappings();
        WIREMOCK.stubFor(get(urlEqualTo("/jwks"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(jwkSet.toJSONObject().toJSONString())));
    }

    private static RSAKey newKey(String kid) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair kp = gen.generateKeyPair();
        return new RSAKey.Builder((RSAPublicKey) kp.getPublic())
                .privateKey((RSAPrivateKey) kp.getPrivate())
                .keyID(kid)
                .build();
    }
}
