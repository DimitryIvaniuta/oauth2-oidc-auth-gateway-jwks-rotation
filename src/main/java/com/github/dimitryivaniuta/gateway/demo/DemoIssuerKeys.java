package com.github.dimitryivaniuta.gateway.demo;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Component;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

/**
 * In-app demo issuer key store used only in {@code demo-issuer} profile.
 *
 * <p>It maintains a list of RSA keys (current + previous) to simulate rotation.</p>
 */
@Slf4j
@Component
public class DemoIssuerKeys {

    @Getter
    private final List<RSAKey> keys = new ArrayList<>();

    public DemoIssuerKeys() {
        rotate();
    }

    public synchronized RSAKey current() {
        return keys.get(0);
    }

    public synchronized void rotate() {
        keys.add(0, newRsaKey());
        // keep last 3 keys for demo purposes
        while (keys.size() > 3) {
            keys.remove(keys.size() - 1);
        }
        log.info("Demo issuer rotated keys. Current kid={}", keys.get(0).getKeyID());
    }

    public synchronized JWKSet jwkSet() {
        return new JWKSet(new ArrayList<>(keys));
    }

    private RSAKey newRsaKey() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair kp = gen.generateKeyPair();

            RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
            RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();

            return new RSAKey.Builder(pub)
                    .privateKey(priv)
                    .keyID("kid-" + UUID.randomUUID())
                    .issueTime(java.util.Date.from(Instant.now()))
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to generate RSA key", e);
        }
    }
}
