#schema.sql

-- schema.sql
-- Run this to initialize the database

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS scans;

-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT 0
);

-- Scans table
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    target_ip TEXT NOT NULL,
    start_port INTEGER NOT NULL,
    end_port INTEGER NOT NULL,
    open_ports TEXT,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);