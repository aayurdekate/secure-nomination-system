-- ============================================
-- Waitlist Management System - Database Setup
-- ============================================

-- Step 1: Create the database
-- Run this command separately in psql or pgAdmin:
CREATE DATABASE secure_db;

-- Step 2: Connect to the database
-- \c secure_db

-- Step 3: Enable UUID extension (required for UUID generation)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Step 4: Create the users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    address TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Step 5: Create an index on email for faster lookups
CREATE INDEX idx_users_email ON users(email);

-- ============================================
-- Usage Instructions:
-- ============================================
-- 1. Open your terminal and connect to PostgreSQL:
--    psql -U postgres
--
-- 2. Create the database:
--    CREATE DATABASE secure_db;
--
-- 3. Connect to the new database:
--    \c secure_db
--
-- 4. Run the remaining commands (UUID extension and table creation)
--    Or run this entire file:
--    \i /path/to/database.sql
-- ============================================
