create table if not exists auth_audit (
    id uuid primary key,
    created_at timestamptz not null,
    correlation_id varchar(64) not null,
    subject varchar(256),
    issuer varchar(512) not null,
    audience varchar(256) not null,
    kid varchar(128),
    path varchar(512) not null,
    method varchar(16) not null,
    outcome varchar(32) not null,
    reason varchar(512)
);

create index if not exists idx_auth_audit_created_at on auth_audit(created_at);
create index if not exists idx_auth_audit_subject on auth_audit(subject);
