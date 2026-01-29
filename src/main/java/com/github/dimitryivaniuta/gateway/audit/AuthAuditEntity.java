package com.github.dimitryivaniuta.gateway.audit;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

/**
 * Postgres entity that stores request-level authentication audit events.
 */
@Data
@Entity
@Table(name = "auth_audit")
public class AuthAuditEntity {

    @Id
    private UUID id;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "correlation_id", nullable = false, length = 64)
    private String correlationId;

    @Column(name = "subject", length = 256)
    private String subject;

    @Column(name = "issuer", nullable = false, length = 512)
    private String issuer;

    @Column(name = "audience", nullable = false, length = 256)
    private String audience;

    @Column(name = "kid", length = 128)
    private String kid;

    @Column(name = "path", nullable = false, length = 512)
    private String path;

    @Column(name = "method", nullable = false, length = 16)
    private String method;

    @Enumerated(EnumType.STRING)
    @Column(name = "outcome", nullable = false, length = 32)
    private AuthAuditOutcome outcome;

    @Column(name = "reason", length = 512)
    private String reason;
}
