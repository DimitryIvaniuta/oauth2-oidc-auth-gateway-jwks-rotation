package com.github.dimitryivaniuta.gateway.config;

import com.github.dimitryivaniuta.gateway.audit.AuthAuditService;
import com.github.dimitryivaniuta.gateway.audit.SuccessfulAuthAuditFilter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Filter configuration.
 */
@Configuration
public class AuditFilterConfig {

    @Bean
    SuccessfulAuthAuditFilter successfulAuthAuditFilter(AuthAuditService auditService) {
        return new SuccessfulAuthAuditFilter(auditService);
    }
}
