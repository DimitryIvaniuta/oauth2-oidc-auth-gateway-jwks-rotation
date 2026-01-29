package com.github.dimitryivaniuta.gateway.config;

import java.net.URI;
import java.time.Duration;

import com.github.dimitryivaniuta.gateway.audit.SuccessfulAuthAuditFilter;
import com.github.dimitryivaniuta.gateway.jwks.RedisCachingJwkSource;
import com.github.dimitryivaniuta.gateway.observability.CorrelationIdFilter;
import com.github.dimitryivaniuta.gateway.security.AuthoritiesMapper;
import com.github.dimitryivaniuta.gateway.security.AuditingAccessDeniedHandler;
import com.github.dimitryivaniuta.gateway.security.AuditingAuthenticationEntryPoint;
import com.github.dimitryivaniuta.gateway.security.JwtValidatorsFactory;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.JWKSource;

import lombok.RequiredArgsConstructor;

/**
 * Spring Security configuration.
 *
 * <p>The gateway works as an OAuth2 Resource Server. It validates JWT signatures via JWKS (with rotation)
 * and enforces issuer/audience validation.</p>
 */
@Configuration
@EnableConfigurationProperties(AuthProperties.class)
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthProperties authProperties;
    private final RedisCachingJwkSource jwkSource;
    private final AuthoritiesMapper authoritiesMapper;
    private final AuditingAuthenticationEntryPoint entryPoint;
    private final AuditingAccessDeniedHandler accessDeniedHandler;
    private final SuccessfulAuthAuditFilter successfulAuthAuditFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(entryPoint)
                .accessDeniedHandler(accessDeniedHandler)
            )
            .authorizeHttpRequests(auth -> auth
                // demo issuer endpoints (public)
                .requestMatchers("/.well-known/**").permitAll()
                .requestMatchers("/oauth2/jwks").permitAll()
                .requestMatchers("/api/demo/**").permitAll()
                .requestMatchers("/actuator/health").permitAll()

                // admin
                .requestMatchers(HttpMethod.POST, "/api/admin/**").hasRole("ADMIN")

                // everything else secured
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder)
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            );

        http.addFilterBefore(new CorrelationIdFilter(), BasicAuthenticationFilter.class);
        http.addFilterAfter(successfulAuthAuditFilter, BearerTokenAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        URI jwksUri = URI.create(authProperties.getJwksUri());
        jwkSource.configure(
                jwksUri,
                authProperties.getJwksCache().getRedisKey(),
                authProperties.getJwksCache().getTtl(),
                Duration.ofSeconds(2)
        );

        JWKSource<SecurityContext> source = jwkSource;
        NimbusJwtDecoder decoder = new NimbusJwtDecoder(source);
        decoder.setJwtValidator(JwtValidatorsFactory.issuerAndAudience(
                authProperties.getIssuer(),
                authProperties.getAudience()
        ));
        return decoder;
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesMapper);
        converter.setPrincipalClaimName("sub");
        return converter;
    }
}
