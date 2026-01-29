package com.github.dimitryivaniuta.gateway.audit;

import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

/**
 * Publishes auth audit events to Kafka for monitoring.
 */
@Component
@RequiredArgsConstructor
public class AuthAuditPublisher {

    public static final String TOPIC = "auth-audit-events";

    private final KafkaTemplate<String, AuthAuditEvent> kafkaTemplate;

    public void publish(AuthAuditEvent event) {
        String key = event.getSubject() != null ? event.getSubject() : event.getCorrelationId();
        kafkaTemplate.send(TOPIC, key, event);
    }
}
