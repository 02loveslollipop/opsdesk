-- OpsDesk Database Initialization Script (Fixed / Secure Version)

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS tickets (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL DEFAULT 'open'
);

-- Seed users with secure Argon2 password hashes
-- alice / alice123
-- bob   / bob123
-- admin / admin123
INSERT INTO users (username, password, role) VALUES
('alice', '$argon2id$v=19$m=65536,t=3,p=4$3kxrWBkGxEQ7hJ7e9Hu0Kw$9TltCpDoInpvTKBTFDP+6nnbVdDetdG7Iawl2izk/h4', 'user'),
('bob', '$argon2id$v=19$m=65536,t=3,p=4$KR/Ez4Q3jy1Sx50uLQQ/iA$5duqQHGr+j/R3dy/Szd345bQTcq3m5ir1pg6TXD1lKs', 'user'),
('admin', '$argon2id$v=19$m=65536,t=3,p=4$NmIvcmvYXkNpnWO5ULSrOA$K0zu2C0r6ptxBDn+n1pFCIcLQKoHxFV3ZjGWvV9j938', 'admin')
ON CONFLICT (username) DO NOTHING;

-- Seed initial support tickets
INSERT INTO tickets (title, description, owner_id, status) VALUES
('Production API High Latency', 'P99 latency exceeding 800ms in us-east-1 region. Worker queue buildup observed.', 1, 'open'),
('Database Replica Replication Lag', 'Replica 2 lagging by >120 seconds. WAL receiver connection dropping intermittently.', 2, 'in_progress'),
('SSL/TLS Certificate Renewal', 'Internal wildcard cert *.internal.opsdesk expires in 7 days. Automated ACME challenge pending.', 1, 'open'),
('Audit Log Shipper Failure', 'Logstash shipper disk full on syslog node-03. Need log rotation policy review.', 3, 'closed')
ON CONFLICT DO NOTHING;
