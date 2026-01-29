package com.github.dimitryivaniuta.gateway.audit;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.github.dimitryivaniuta.gateway.config.AuthProperties;
import com.github.dimitryivaniuta.gateway.observability.CorrelationIdFilter;

import org.slf4j.MDC;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

/**
 * Stores audit events in Postgres and publishes them to Kafka.
 */
@Service
@RequiredArgsConstructor
public class AuthAuditService {

    private final AuthProperties authProperties;
    private final AuthAuditRepository repository;
    private final AuthAuditPublisher publisher;

    @Transactional
    public AuthAuditEntity accepted(HttpServletRequest request, Jwt jwt) {
        String cid = correlationId();
        String kid = Optional.ofNullable(jwt.getHeaders().get("kid")).map(Object::toString).orElse(null);

        AuthAuditEntity e = base(request, jwt.getSubject(), kid, AuthAuditOutcome.ACCEPTED, null, cid);
        repository.save(e);
        publisher.publish(toEvent(e));
        return e;
    }

    @Transactional
    public AuthAuditEntity rejected(HttpServletRequest request, String reason) {
        String cid = correlationId();
        AuthAuditEntity e = base(request, null, null, AuthAuditOutcome.REJECTED, reason, cid);
        repository.save(e);
        publisher.publish(toEvent(e));
        return e;
    }

    @Transactional
    public AuthAuditEntity forbidden(HttpServletRequest request, String subject, String kid, String reason) {
        String cid = correlationId();
        AuthAuditEntity e = base(request, subject, kid, AuthAuditOutcome.FORBIDDEN, reason, cid);
        repository.save(e);
        publisher.publish(toEvent(e));
        return e;
    }

    private AuthAuditEntity base(HttpServletRequest request, String subject, String kid, AuthAuditOutcome outcome, String reason, String cid) {
        AuthAuditEntity e = new AuthAuditEntity();
        e.setId(UUID.randomUUID());
        e.setCreatedAt(Instant.now());
        e.setCorrelationId(cid);
        e.setSubject(subject);
        e.setIssuer(authProperties.getIssuer());
        e.setAudience(authProperties.getAudience());
        e.setKid(kid);
        e.setPath(request.getRequestURI());
        e.setMethod(request.getMethod());
        e.setOutcome(outcome);
        e.setReason(reason);
        return e;
    }

    private AuthAuditEvent toEvent(AuthAuditEntity e) {
        return AuthAuditEvent.builder()
                .id(e.getId())
                .createdAt(e.getCreatedAt())
                .correlationId(e.getCorrelationId())
                .subject(e.getSubject())
                .issuer(e.getIssuer())
                .audience(e.getAudience())
                .kid(e.getKid())
                .path(e.getPath())
                .method(e.getMethod())
                .outcome(e.getOutcome())
                .reason(e.getReason())
                .build();
    }

    private String correlationId() {
        return Optional.ofNullable(MDC.get(CorrelationIdFilter.MDC_KEY)).orElse("n/a");
    }
}
