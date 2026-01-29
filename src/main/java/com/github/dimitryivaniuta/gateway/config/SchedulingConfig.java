package com.github.dimitryivaniuta.gateway.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Enables scheduling for periodic JWKS refresh.
 */
@Configuration
@EnableScheduling
public class SchedulingConfig {
}
