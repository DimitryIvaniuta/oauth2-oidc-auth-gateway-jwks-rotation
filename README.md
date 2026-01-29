# oauth2-oidc-auth-gateway-jwks-rotation

Spring Boot 3.5.9 (Java 21) Auth Gateway: JWT validation with Redis-cached JWKS + seamless key rotation, claim→role mapping, Postgres/Flyway audit log, Kafka auth events, full integration tests + Postman.

## What you get

- **JWT validation**: issuer, audience, exp, signature (JWKS).
- **JWKS rotation with no downtime**:
  - JWKS is fetched over HTTP and cached in **Redis** (shared cache) + local in-memory cache.
  - On unknown `kid`, the gateway **forces refresh** and retries validation (new keys work immediately).
  - Old tokens continue to validate as long as their `kid` is still in JWKS and token is not expired.
- **Claim mapping → authorities**:
  - `roles` → `ROLE_*`
  - `scope` or `scp` → `SCOPE_*`
  - `permissions` → `PERM_*`
- **Audit** stored in **Postgres** (Flyway).
- **Auth events** published to **Kafka** topic `auth-audit-events`.
- **Redis** used for JWKS cache (multi-instance friendly).
- **Postman** collection to test (including a built-in demo token mint endpoint in `demo-issuer` profile).

## Modules

Single application: `auth-gateway`.

## Local run (Docker)

1. Start infrastructure:

```bash
docker compose up -d
```

2. Run the app (Linux/macOS):

```bash
./gradlew bootRun --args='--spring.profiles.active=local,demo-issuer'
```

Windows:

```powershell
gradlew.bat bootRun --args="--spring.profiles.active=local,demo-issuer"
```

The demo issuer endpoints will be available in the same app:
- `GET /.well-known/openid-configuration`
- `GET /oauth2/jwks`
- `GET /api/demo/token?sub=john&roles=USER,ADMIN&permissions=orders:read,orders:write`

## Try with Postman

Import:
- `postman/oauth2-oidc-auth-gateway-jwks-rotation.postman_collection.json`
- `postman/oauth2-oidc-auth-gateway-jwks-rotation.postman_environment.json`

Steps:
1. Call **Demo - Mint JWT** to fetch a token and auto-store it as `{token}`.
2. Call **User - Me** (should return claims + mapped authorities).
3. Call **Admin - Force JWKS refresh** (requires ADMIN role in the token).

## Tests

```bash
./gradlew test
```

Integration tests use:
- **Testcontainers**: Postgres + Redis
- **Embedded Kafka**: via `spring-kafka-test`
- **WireMock**: to simulate JWKS rotation (key1 → key2).

## Configuration highlights

See `src/main/resources/application.yml` and `application-local.yml`.

Key props:

- `auth.issuer`
- `auth.audience`
- `auth.jwksUri`
- `auth.jwksCache.redisKey`
- `auth.jwksCache.ttl`

## Repository

Suggested GitHub repository name: **oauth2-oidc-auth-gateway-jwks-rotation**
