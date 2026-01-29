package com.github.dimitryivaniuta.gateway.containers;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Shared Testcontainers for integration tests.
 */
public final class Containers {

    private Containers() {}

    public static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(DockerImageName.parse("postgres:16"))
            .withDatabaseName("auth_gateway")
            .withUsername("auth")
            .withPassword("auth");

    public static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7"))
            .withExposedPorts(6379);

    static {
        POSTGRES.start();
        REDIS.start();
    }
}
