/**
 * Secure Nomination System - Backend Server
 * 
 * Security Features Demonstrated:
 * 1. Bcrypt password hashing (10 rounds)
 * 2. JWT token authentication
 * 3. Parameterized SQL queries (SQL injection prevention)
 * 4. Input validation
 * 5. CORS protection
 * 6. Protected routes middleware
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();

// ============================================
// SECURITY: JWT Secret (in production, use env variable)
// ============================================
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const JWT_EXPIRES_IN = '24h';

// ============================================
// Middleware Configuration
// ============================================

// SECURITY: CORS - Only allow requests from trusted origin
app.use(cors({
    origin: 'http://localhost:3002',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

app.use(express.json());

// ============================================
// Database Connection
// ============================================

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ Database connection error:', err.stack);
    } else {
        console.log('✅ Connected to PostgreSQL');
        release();
    }
});

// ============================================
// SECURITY: Authentication Middleware
// ============================================

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access denied. No token provided.'
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({
            success: false,
            message: 'Invalid or expired token.'
        });
    }
};

// ============================================
// SECURITY: Input Validation Helpers
// ============================================

const validateEmail = (email) => {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
};

const validatePassword = (password) => {
    // Minimum 8 characters
    return password && password.length >= 8;
};

// ============================================
// AUTH ROUTES
// ============================================

/**
 * POST /api/register
 * SECURITY: Password hashed with bcrypt before storage
 */
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;

        // SECURITY: Input validation
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid email format'
            });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters'
            });
        }

        // Check if email exists
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE email = $1',
            [email]
        );

        if (existingUser.rows.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'Email already registered'
            });
        }

        // SECURITY: Hash password with bcrypt (10 salt rounds)
        const saltRounds = 10;
        const password_hash = await bcrypt.hash(password, saltRounds);

        // SECURITY: Parameterized query prevents SQL injection
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, address) VALUES ($1, $2, $3) RETURNING id, email, created_at',
            [email, password_hash, name || null]
        );

        const user = result.rows[0];

        // Generate JWT token
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );

        console.log(`✅ New user registered: ${email}`);

        res.status(201).json({
            success: true,
            message: 'Registration successful',
            token,
            user: { id: user.id, email: user.email, name: name }
        });

    } catch (error) {
        console.error('❌ Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Registration failed. Please try again.'
        });
    }
});

/**
 * POST /api/login
 * SECURITY: Compares password hash, returns JWT token
 */
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        // SECURITY: Parameterized query
        const result = await pool.query(
            'SELECT id, email, password_hash, address as name FROM users WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        const user = result.rows[0];

        // SECURITY: Compare password with stored hash
        const validPassword = await bcrypt.compare(password, user.password_hash);

        if (!validPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );

        console.log(`✅ User logged in: ${email}`);

        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: { id: user.id, email: user.email, name: user.name }
        });

    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed. Please try again.'
        });
    }
});

// ============================================
// ADDRESS ROUTES (Protected)
// ============================================

/**
 * GET /api/addresses
 * Get all addresses for the logged-in user
 */
app.get('/api/addresses', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM addresses WHERE user_id = $1 ORDER BY created_at DESC',
            [req.user.userId]
        );

        res.json({
            success: true,
            addresses: result.rows
        });
    } catch (error) {
        console.error('❌ Get addresses error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch addresses'
        });
    }
});

/**
 * POST /api/addresses
 * Add a new address for the logged-in user
 * AUDIT: Logs creation in address_history
 */
app.post('/api/addresses', authenticateToken, async (req, res) => {
    try {
        const { label, street, city, state, postal_code, country } = req.body;

        if (!label || !street || !city || !country) {
            return res.status(400).json({
                success: false,
                message: 'Label, street, city, and country are required'
            });
        }

        const result = await pool.query(
            `INSERT INTO addresses (user_id, label, street, city, state, postal_code, country)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING *`,
            [req.user.userId, label, street, city, state || null, postal_code || null, country]
        );

        const newAddress = result.rows[0];

        // AUDIT: Log address creation
        await pool.query(
            `INSERT INTO address_history 
             (address_id, user_id, action, new_label, new_street, new_city, new_state, new_postal_code, new_country)
             VALUES ($1, $2, 'CREATED', $3, $4, $5, $6, $7, $8)`,
            [newAddress.id, req.user.userId, label, street, city, state, postal_code, country]
        );

        console.log(`✅ Address added for user: ${req.user.email}`);

        res.status(201).json({
            success: true,
            message: 'Address added successfully',
            address: newAddress
        });
    } catch (error) {
        console.error('❌ Add address error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add address'
        });
    }
});

/**
 * PUT /api/addresses/:id
 * Update an address - TRACKS OLD AND NEW VALUES
 * AUDIT: Logs both old and new address in history
 */
app.put('/api/addresses/:id', authenticateToken, async (req, res) => {
    try {
        const { label, street, city, state, postal_code, country } = req.body;

        if (!label || !street || !city || !country) {
            return res.status(400).json({
                success: false,
                message: 'Label, street, city, and country are required'
            });
        }

        // Get current address (old values)
        const oldResult = await pool.query(
            'SELECT * FROM addresses WHERE id = $1 AND user_id = $2',
            [req.params.id, req.user.userId]
        );

        if (oldResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Address not found'
            });
        }

        const oldAddress = oldResult.rows[0];

        // Update address
        const result = await pool.query(
            `UPDATE addresses 
             SET label = $1, street = $2, city = $3, state = $4, postal_code = $5, country = $6
             WHERE id = $7 AND user_id = $8
             RETURNING *`,
            [label, street, city, state || null, postal_code || null, country, req.params.id, req.user.userId]
        );

        const newAddress = result.rows[0];

        // AUDIT: Log address update with OLD and NEW values
        await pool.query(
            `INSERT INTO address_history 
             (address_id, user_id, action, 
              old_label, old_street, old_city, old_state, old_postal_code, old_country,
              new_label, new_street, new_city, new_state, new_postal_code, new_country)
             VALUES ($1, $2, 'UPDATED', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
            [req.params.id, req.user.userId,
            oldAddress.label, oldAddress.street, oldAddress.city, oldAddress.state, oldAddress.postal_code, oldAddress.country,
                label, street, city, state, postal_code, country]
        );

        console.log(`✅ Address updated for user: ${req.user.email} (tracked old → new)`);

        res.json({
            success: true,
            message: 'Address updated successfully',
            address: newAddress
        });
    } catch (error) {
        console.error('❌ Update address error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update address'
        });
    }
});

/**
 * DELETE /api/addresses/:id
 * Delete an address
 * AUDIT: Logs deletion with old values in history
 */
app.delete('/api/addresses/:id', authenticateToken, async (req, res) => {
    try {
        // Get address before deleting (for history)
        const oldResult = await pool.query(
            'SELECT * FROM addresses WHERE id = $1 AND user_id = $2',
            [req.params.id, req.user.userId]
        );

        if (oldResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Address not found'
            });
        }

        const oldAddress = oldResult.rows[0];

        // AUDIT: Log deletion with old values
        await pool.query(
            `INSERT INTO address_history 
             (address_id, user_id, action, old_label, old_street, old_city, old_state, old_postal_code, old_country)
             VALUES ($1, $2, 'DELETED', $3, $4, $5, $6, $7, $8)`,
            [req.params.id, req.user.userId,
            oldAddress.label, oldAddress.street, oldAddress.city, oldAddress.state, oldAddress.postal_code, oldAddress.country]
        );

        // Delete the address
        await pool.query(
            'DELETE FROM addresses WHERE id = $1 AND user_id = $2',
            [req.params.id, req.user.userId]
        );

        console.log(`✅ Address deleted for user: ${req.user.email} (history preserved)`);

        res.json({
            success: true,
            message: 'Address deleted successfully'
        });
    } catch (error) {
        console.error('❌ Delete address error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete address'
        });
    }
});

/**
 * GET /api/addresses/history
 * Get address change history for the logged-in user
 * TRACEABILITY: Shows all address changes over time
 */
app.get('/api/addresses/history', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM address_history 
             WHERE user_id = $1 
             ORDER BY changed_at DESC`,
            [req.user.userId]
        );

        res.json({
            success: true,
            history: result.rows
        });
    } catch (error) {
        console.error('❌ Get address history error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch address history'
        });
    }
});

/**
 * GET /api/addresses/history/all
 * Get ALL address changes (admin view for traceability)
 */
app.get('/api/addresses/history/all', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT h.*, u.email, u.address as user_name
             FROM address_history h
             JOIN users u ON h.user_id = u.id
             ORDER BY h.changed_at DESC`
        );

        res.json({
            success: true,
            history: result.rows
        });
    } catch (error) {
        console.error('❌ Get all address history error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch address history'
        });
    }
});

// ============================================
// NOMINATION ROUTES (Protected)
// ============================================

/**
 * GET /api/users
 * Get all users (for nomination dropdown)
 */
app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, email, address as name FROM users WHERE id != $1',
            [req.user.userId]
        );

        res.json({
            success: true,
            users: result.rows
        });
    } catch (error) {
        console.error('❌ Get users error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch users'
        });
    }
});

/**
 * POST /api/nominations
 * Nominate another user
 */
app.post('/api/nominations', authenticateToken, async (req, res) => {
    try {
        const { nominee_id, reason } = req.body;

        if (!nominee_id) {
            return res.status(400).json({
                success: false,
                message: 'Nominee is required'
            });
        }

        if (nominee_id === req.user.userId) {
            return res.status(400).json({
                success: false,
                message: 'You cannot nominate yourself'
            });
        }

        // Check if nomination already exists
        const existing = await pool.query(
            'SELECT id FROM nominations WHERE nominator_id = $1 AND nominee_id = $2',
            [req.user.userId, nominee_id]
        );

        if (existing.rows.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'You have already nominated this user'
            });
        }

        const result = await pool.query(
            `INSERT INTO nominations (nominator_id, nominee_id, reason)
             VALUES ($1, $2, $3)
             RETURNING *`,
            [req.user.userId, nominee_id, reason || null]
        );

        console.log(`✅ Nomination created by: ${req.user.email}`);

        res.status(201).json({
            success: true,
            message: 'Nomination submitted successfully',
            nomination: result.rows[0]
        });
    } catch (error) {
        console.error('❌ Create nomination error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create nomination'
        });
    }
});

/**
 * GET /api/nominations/given
 * Get nominations made BY the logged-in user
 */
app.get('/api/nominations/given', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT n.*, u.email as nominee_email, u.address as nominee_name
             FROM nominations n
             JOIN users u ON n.nominee_id = u.id
             WHERE n.nominator_id = $1
             ORDER BY n.created_at DESC`,
            [req.user.userId]
        );

        res.json({
            success: true,
            nominations: result.rows
        });
    } catch (error) {
        console.error('❌ Get given nominations error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch nominations'
        });
    }
});

/**
 * GET /api/nominations/received
 * Get nominations received BY the logged-in user
 */
app.get('/api/nominations/received', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT n.*, u.email as nominator_email, u.address as nominator_name
             FROM nominations n
             JOIN users u ON n.nominator_id = u.id
             WHERE n.nominee_id = $1
             ORDER BY n.created_at DESC`,
            [req.user.userId]
        );

        res.json({
            success: true,
            nominations: result.rows
        });
    } catch (error) {
        console.error('❌ Get received nominations error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch nominations'
        });
    }
});

/**
 * GET /api/nominations/trace/:userId
 * Trace the nomination chain for a user (who nominated them, their addresses)
 */
app.get('/api/nominations/trace/:userId', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT 
                n.id as nomination_id,
                n.reason,
                n.created_at as nominated_at,
                nominator.id as nominator_id,
                nominator.email as nominator_email,
                nominator.address as nominator_name,
                nominee.id as nominee_id,
                nominee.email as nominee_email,
                nominee.address as nominee_name,
                json_agg(json_build_object(
                    'label', a.label,
                    'street', a.street,
                    'city', a.city,
                    'country', a.country
                )) FILTER (WHERE a.id IS NOT NULL) as nominator_addresses
             FROM nominations n
             JOIN users nominator ON n.nominator_id = nominator.id
             JOIN users nominee ON n.nominee_id = nominee.id
             LEFT JOIN addresses a ON nominator.id = a.user_id
             WHERE n.nominee_id = $1
             GROUP BY n.id, nominator.id, nominee.id
             ORDER BY n.created_at DESC`,
            [req.params.userId]
        );

        res.json({
            success: true,
            trace: result.rows
        });
    } catch (error) {
        console.error('❌ Trace nominations error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to trace nominations'
        });
    }
});

/**
 * GET /api/nominations/all
 * Get ALL nominations with full details including addresses (admin view)
 * TRACEABILITY: Shows who nominated whom AND their location
 */
app.get('/api/nominations/all', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT 
                n.id,
                n.reason,
                n.created_at,
                nominator.email as nominator_email,
                nominator.address as nominator_name,
                nominee.email as nominee_email,
                nominee.address as nominee_name,
                (SELECT city FROM addresses WHERE user_id = nominator.id LIMIT 1) as nominator_city,
                (SELECT city FROM addresses WHERE user_id = nominee.id LIMIT 1) as nominee_city
             FROM nominations n
             JOIN users nominator ON n.nominator_id = nominator.id
             JOIN users nominee ON n.nominee_id = nominee.id
             ORDER BY n.created_at DESC`
        );

        res.json({
            success: true,
            nominations: result.rows
        });
    } catch (error) {
        console.error('❌ Get all nominations error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch nominations'
        });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// ============================================
// Server Start
// ============================================

const PORT = process.env.PORT || 5001;

app.listen(PORT, () => {
    console.log('');
    console.log('🔐 ================================');
    console.log('   Secure Nomination System');
    console.log('🔐 ================================');
    console.log(`   Port: ${PORT}`);
    console.log('   Security Features:');
    console.log('     ✓ Bcrypt Password Hashing');
    console.log('     ✓ JWT Authentication');
    console.log('     ✓ Parameterized Queries');
    console.log('     ✓ Input Validation');
    console.log('     ✓ CORS Protection');
    console.log('================================');
    console.log('');
});
