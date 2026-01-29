package com.github.dimitryivaniuta.gateway.audit;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Repository for authentication audit events.
 */
public interface AuthAuditRepository extends JpaRepository<AuthAuditEntity, UUID> {
}
