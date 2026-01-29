package com.github.dimitryivaniuta.gateway.audit;

import java.time.Instant;
import java.util.UUID;

import lombok.Builder;
import lombok.Value;

/**
 * Kafka event emitted for monitoring/analytics.
 */
@Value
@Builder
public class AuthAuditEvent {
    UUID id;
    Instant createdAt;
    String correlationId;
    String subject;
    String issuer;
    String audience;
    String kid;
    String path;
    String method;
    AuthAuditOutcome outcome;
    String reason;
}
