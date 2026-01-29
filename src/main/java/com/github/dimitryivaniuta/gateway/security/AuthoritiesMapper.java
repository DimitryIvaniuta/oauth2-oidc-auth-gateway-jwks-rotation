package com.github.dimitryivaniuta.gateway.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/**
 * Maps JWT claims to Spring Security authorities.
 *
 * <p>Supported claims:</p>
 * <ul>
 *   <li>{@code roles}: array or comma-separated string -&gt; {@code ROLE_*}</li>
 *   <li>{@code scope} or {@code scp}: space-separated string or array -&gt; {@code SCOPE_*}</li>
 *   <li>{@code permissions}: array or comma-separated -&gt; {@code PERM_*}</li>
 * </ul>
 */
@Component
public class AuthoritiesMapper implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        List<GrantedAuthority> out = new ArrayList<>();
        out.addAll(prefixFromClaim(jwt, "roles", "ROLE_"));
        out.addAll(prefixFromClaim(jwt, "permissions", "PERM_"));

        // scope can be "scope": "a b" or "scp": ["a","b"]
        out.addAll(prefixFromClaim(jwt, "scope", "SCOPE_"));
        out.addAll(prefixFromClaim(jwt, "scp", "SCOPE_"));

        return out;
    }

    private List<GrantedAuthority> prefixFromClaim(Jwt jwt, String claim, String prefix) {
        Object v = jwt.getClaims().get(claim);
        if (v == null) return List.of();

        List<String> values = new ArrayList<>();

        if (v instanceof String s) {
            // allow "a b" or "a,b"
            String normalized = s.replace(",", " ");
            for (String token : normalized.split("\\s+")) {
                if (!token.isBlank()) values.add(token.trim());
            }
        } else if (v instanceof Collection<?> c) {
            for (Object o : c) {
                Optional.ofNullable(o).map(Object::toString).filter(str -> !str.isBlank()).ifPresent(values::add);
            }
        } else {
            values.add(v.toString());
        }

        List<GrantedAuthority> out = new ArrayList<>();
        for (String val : values) {
            out.add(new SimpleGrantedAuthority(prefix + val));
        }
        return out;
    }
}
