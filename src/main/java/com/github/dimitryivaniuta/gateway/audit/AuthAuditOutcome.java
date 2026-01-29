package com.github.dimitryivaniuta.gateway.audit;

/**
 * Outcome of authentication/authorization evaluation for a request.
 */
public enum AuthAuditOutcome {
    ACCEPTED,
    REJECTED,
    FORBIDDEN
}
