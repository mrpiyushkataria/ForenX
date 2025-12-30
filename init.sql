-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create tables
CREATE TABLE IF NOT EXISTS log_events (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    source VARCHAR(50) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    method VARCHAR(10),
    endpoint VARCHAR(500),
    status INTEGER,
    response_size BIGINT DEFAULT 0,
    payload TEXT,
    raw TEXT NOT NULL,
    risk_score INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_log_events_timestamp ON log_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_log_events_ip ON log_events(ip);
CREATE INDEX IF NOT EXISTS idx_log_events_endpoint ON log_events(endpoint);
CREATE INDEX IF NOT EXISTS idx_log_events_source ON log_events(source);
