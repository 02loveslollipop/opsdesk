-- OpsDesk Database Initialization Script

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

-- Seed users (vulnerable initial version stores plain text passwords)
INSERT INTO users (username, password, role) VALUES
('alice', 'alice123', 'user'),
('bob', 'bob123', 'user'),
('admin', 'admin123', 'admin')
ON CONFLICT (username) DO NOTHING;

-- Seed initial support tickets
INSERT INTO tickets (title, description, owner_id, status) VALUES
('Production API High Latency', 'P99 latency exceeding 800ms in us-east-1 region. Worker queue buildup observed.', 1, 'open'),
('Database Replica Replication Lag', 'Replica 2 lagging by >120 seconds. WAL receiver connection dropping intermittently.', 2, 'in_progress'),
('SSL/TLS Certificate Renewal', 'Internal wildcard cert *.internal.opsdesk expires in 7 days. Automated ACME challenge pending.', 1, 'open'),
('Audit Log Shipper Failure', 'Logstash shipper disk full on syslog node-03. Need log rotation policy review.', 3, 'closed')
ON CONFLICT DO NOTHING;
