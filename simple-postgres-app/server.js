const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Serve static files from the current directory
app.use(express.static(__dirname));

// PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    // Log the decoded token for debugging
    console.log('Decoded token:', decoded);
    
    if (!decoded.id) {
      console.error('Token missing user ID:', decoded);
      return res.status(403).json({ error: 'Invalid token format' });
    }
    
    req.user = decoded;
    next();
  });
};

// Test endpoint
app.get('/api/test', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ message: 'Connected to PostgreSQL!', time: result.rows[0].now });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database connection failed' });
  }
});

// Create table if not exists
app.get('/api/setup', async (req, res) => {
  try {
    const client = await pool.connect();
    
    // Create users table if it doesn't exist
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        phone VARCHAR(20),
        address TEXT,
        balance DECIMAL(10, 2) DEFAULT 0.00,
        reset_token VARCHAR(100),
        reset_token_expiry TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
      )
    `);

    // Add balance column if it doesn't exist
    await client.query(`
      DO $$ 
      BEGIN
        BEGIN
          ALTER TABLE users ADD COLUMN balance DECIMAL(10, 2) DEFAULT 0.00;
        EXCEPTION
          WHEN duplicate_column THEN 
            NULL;
        END;
      END $$;
    `);

    client.release();
    res.json({ message: 'Database setup completed successfully' });
  } catch (error) {
    console.error('Error setting up database:', error);
    res.status(500).json({ error: 'Database setup failed' });
  }
});

// Register new user
app.post('/api/register', async (req, res) => {
  const { name, email, password, phone, address } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, password, phone, address, balance) VALUES ($1, $2, $3, $4, $5, 0) RETURNING id, name, email, role',
      [name, email, hashedPassword, phone, address]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

    // Generate JWT token with user ID
    const token = jwt.sign(
      { 
        id: user.id,
        email: user.email,
        role: user.role,
        name: user.name
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed', details: err.message });
  }
});

// Get current user profile
app.get('/api/users/me', authenticateToken, async (req, res) => {
    let client;
    try {
        console.log('Fetching user profile for ID:', req.user.id);
        console.log('Decoded user:', req.user);
        
        client = await pool.connect();
        console.log('Database connection established');
        
        // First check if user exists
        const checkResult = await client.query('SELECT id FROM users WHERE id = $1', [req.user.id]);
        if (checkResult.rows.length === 0) {
            console.log('User not found in database for ID:', req.user.id);
            return res.status(404).json({ error: 'User not found' });
        }
        
        const result = await client.query(
            'SELECT id, name, email, role, phone, address, balance FROM users WHERE id = $1',
            [req.user.id]
        );
        
        console.log('Query result:', result.rows);
        
        if (result.rows.length === 0) {
            console.log('User not found for ID:', req.user.id);
            return res.status(404).json({ error: 'User not found' });
        }
        
        const user = result.rows[0];
        console.log('User profile found:', user);
        
        // Ensure balance is a number
        user.balance = parseFloat(user.balance) || 0;
        
        res.json(user);
    } catch (error) {
        console.error('Error in /api/users/me:', error);
        console.error('Error stack:', error.stack);
        console.error('Error details:', {
            message: error.message,
            code: error.code,
            detail: error.detail,
            hint: error.hint
        });
        res.status(500).json({ 
            error: 'Failed to fetch user profile', 
            details: error.message,
            stack: error.stack
        });
    } finally {
        if (client) {
            client.release();
            console.log('Database connection released');
        }
    }
});

// Update current user profile
app.put('/api/users/me', authenticateToken, async (req, res) => {
    let client;
    try {
        console.log('Updating user profile for ID:', req.user.id);
        console.log('Request body:', req.body);
        
        const { name, email, phone, address } = req.body;
        
        if (!name || !email) {
            return res.status(400).json({ error: 'Name and email are required' });
        }

        client = await pool.connect();
        console.log('Database connection established');
        
        // Check if email is already taken by another user
        const emailCheck = await client.query(
            'SELECT id FROM users WHERE email = $1 AND id != $2',
            [email, req.user.id]
        );
        
        if (emailCheck.rows.length > 0) {
            return res.status(400).json({ error: 'Email is already taken' });
        }

        // Update user profile using the ID from the token
        const result = await client.query(
            `UPDATE users 
             SET name = $1, email = $2, phone = $3, address = $4
             WHERE id = $5
             RETURNING id, name, email, role, phone, address, balance`,
            [name, email, phone, address, req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const updatedUser = result.rows[0];
        console.log('Profile updated successfully:', updatedUser);
        
        res.json(updatedUser);
    } catch (error) {
        console.error('Error updating profile:', error);
        console.error('Error details:', {
            message: error.message,
            code: error.code,
            detail: error.detail,
            hint: error.hint
        });
        res.status(500).json({ 
            error: 'Failed to update profile', 
            details: error.message,
            stack: error.stack
        });
    } finally {
        if (client) {
            client.release();
            console.log('Database connection released');
        }
    }
});

// Get user stats
app.get('/api/users/stats', authenticateToken, async (req, res) => {
    try {
        console.log('Fetching user stats for ID:', req.user.id);
        const client = await pool.connect();
        
        // Get total transfers
        const transfersResult = await client.query(`
            SELECT 
                COUNT(*) as total_transfers,
                COALESCE(SUM(CASE WHEN receiver_id = $1 THEN amount ELSE 0 END), 0) as total_received,
                COALESCE(SUM(CASE WHEN sender_id = $1 THEN amount ELSE 0 END), 0) as total_sent
            FROM transactions
            WHERE sender_id = $1 OR receiver_id = $1
        `, [req.user.id]);
        
        client.release();
        
        const stats = {
            totalTransfers: parseInt(transfersResult.rows[0].total_transfers),
            totalReceived: parseFloat(transfersResult.rows[0].total_received),
            totalSent: parseFloat(transfersResult.rows[0].total_sent)
        };
        
        console.log('User stats:', stats);
        res.json(stats);
    } catch (error) {
        console.error('Error fetching user stats:', error);
        res.status(500).json({ error: 'Failed to fetch user stats', details: error.message });
    }
});

// Get total user count (public endpoint)
app.get('/api/users/count', async (req, res) => {
    try {
        const client = await pool.connect();
        const result = await client.query('SELECT COUNT(*) FROM users');
        client.release();
        res.json({ count: parseInt(result.rows[0].count) });
    } catch (error) {
        console.error('Error getting user count:', error);
        res.status(500).json({ error: 'Failed to get user count' });
    }
});

// Get single user by ID (protected)
app.get('/api/users/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    
    try {
        console.log('Fetching user:', id);
        const client = await pool.connect();
        
        const result = await client.query('SELECT * FROM users WHERE id = $1', [id]);
        client.release();
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ error: 'Failed to fetch user', details: error.message });
    }
});

// Get all users (protected)
app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        console.log('Fetching users for:', req.user.id, 'with role:', req.user.role);
        const client = await pool.connect();
        
        let query;
        let params = [];
        const search = req.query.search || '';
        const sortField = req.query.sortField || 'name';
        const sortOrder = req.query.sortOrder || 'asc';

        // Validate sort field to prevent SQL injection
        const validSortFields = ['name', 'email', 'balance', 'role', 'phone', 'address'];
        const validSortOrder = ['asc', 'desc'];
        
        const safeSortField = validSortFields.includes(sortField) ? sortField : 'name';
        const safeSortOrder = validSortOrder.includes(sortOrder.toLowerCase()) ? sortOrder.toUpperCase() : 'ASC';

        if (req.user.role === 'admin') {
            // Admin can see all users with search and sort
            query = `
                SELECT id, name, email, role, phone, address, balance 
                FROM users 
                WHERE name ILIKE $1 OR email ILIKE $1
                ORDER BY ${safeSortField} ${safeSortOrder}
            `;
            params = [`%${search}%`];
        } else {
            // Regular users can only see their own details
            query = 'SELECT id, name, email, role, phone, address, balance FROM users WHERE id = $1';
            params = [req.user.id];
        }

        console.log('Executing query:', query);
        console.log('With parameters:', params);

        const result = await client.query(query, params);
        client.release();

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // If user is not admin, return single user object
        if (req.user.role !== 'admin') {
            res.json(result.rows[0]);
        } else {
            // If admin, return array of users
            res.json(result.rows);
        }
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ 
            error: 'Failed to fetch users',
            details: error.message 
        });
    }
});

// Add new user (protected)
app.post('/api/users', authenticateToken, async (req, res) => {
  const { name, email, password, phone, address } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, password, phone, address) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, email, hashedPassword, phone, address]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add user' });
  }
});

// Update user (protected)
app.put('/api/users/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { name, email, phone, address } = req.body;
    
    try {
        console.log('Updating user:', { id, name, email, phone, address });
        const client = await pool.connect();
        
        // First check if user exists
        const checkResult = await client.query('SELECT id FROM users WHERE id = $1', [id]);
        if (checkResult.rows.length === 0) {
            client.release();
            return res.status(404).json({ error: 'User not found' });
        }
        
        const result = await client.query(
            'UPDATE users SET name = $1, email = $2, phone = $3, address = $4 WHERE id = $5 RETURNING *',
            [name, email, phone, address, id]
        );
        
        client.release();
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Failed to update user', details: error.message });
    }
});

// Delete user (protected)
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const client = await pool.connect();
        const userId = req.params.id === 'me' ? req.user.id : parseInt(req.params.id, 10);

        if (isNaN(userId)) {
            return res.status(400).json({ error: 'Invalid user ID' });
        }

        await client.query('BEGIN');

        // Delete related transactions
        await client.query('DELETE FROM transactions WHERE sender_id = $1 OR receiver_id = $1', [userId]);

        // Delete the user
        const result = await client.query('DELETE FROM users WHERE id = $1', [userId]);

        if (result.rowCount === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'User not found' });
        }

        await client.query('COMMIT');

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Failed to delete user', details: error.message });
    }
});

// Add transactions table setup
app.get('/api/setup-transactions', async (req, res) => {
  try {
    const client = await pool.connect();
    
    // Drop existing transactions table if it exists
    await client.query('DROP TABLE IF EXISTS transactions CASCADE');
    
    // Create transactions table with all required columns
    await client.query(`
      CREATE TABLE transactions (
        id SERIAL PRIMARY KEY,
        sender_id INTEGER REFERENCES users(id),
        receiver_id INTEGER REFERENCES users(id),
        amount DECIMAL(10, 2) NOT NULL,
        status VARCHAR(20) DEFAULT 'completed',
        note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    client.release();
    res.json({ message: 'Transactions table setup completed successfully' });
  } catch (error) {
    console.error('Error setting up transactions table:', error);
    res.status(500).json({ error: 'Transactions table setup failed' });
  }
});

// Get user's transactions
app.get('/api/transactions/my', authenticateToken, async (req, res) => {
    let client;
    try {
        console.log('Fetching transactions for user:', req.user.id);
        client = await pool.connect();
        
        const { type, date } = req.query;
        let query = `
            SELECT 
                t.id,
                t.amount,
                t.status,
                t.created_at,
                COALESCE(t.note, '') as note,
                s.name as sender_name,
                r.name as receiver_name
            FROM transactions t
            LEFT JOIN users s ON t.sender_id = s.id
            LEFT JOIN users r ON t.receiver_id = r.id
            WHERE 1=1
        `;
        const params = [];

        // Add user ID condition
        if (type === 'sent') {
            query += ' AND t.sender_id = $1';
            params.push(req.user.id);
        } else if (type === 'received') {
            query += ' AND t.receiver_id = $1';
            params.push(req.user.id);
        } else {
            query += ' AND (t.sender_id = $1 OR t.receiver_id = $1)';
            params.push(req.user.id);
        }

        if (date) {
            // Convert date to start and end of day in UTC
            const startDate = new Date(date + 'T00:00:00.000Z');
            const endDate = new Date(date + 'T23:59:59.999Z');
            
            query += ' AND t.created_at >= $' + (params.length + 1);
            query += ' AND t.created_at <= $' + (params.length + 2);
            params.push(startDate, endDate);
        }

        query += ' ORDER BY t.created_at DESC';

        console.log('Executing query:', query);
        console.log('With params:', params);

        const result = await client.query(query, params);
        console.log('Found transactions:', result.rows.length);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching transactions:', error);
        res.status(500).json({ 
            error: 'Failed to fetch transactions', 
            details: error.message 
        });
    } finally {
        if (client) {
            client.release();
        }
    }
});

// Add transfer endpoint
app.post('/api/transfer', authenticateToken, async (req, res) => {
    const { fromUserId, toUserId, amount, note } = req.body;
    
    console.log('Transfer request:', { fromUserId, toUserId, amount, note });
    
    if (!fromUserId || !toUserId || !amount || amount <= 0) {
        console.log('Invalid transfer details:', { fromUserId, toUserId, amount });
        return res.status(400).json({ error: 'Invalid transfer details' });
    }

    // Prevent self-transfer
    if (fromUserId === toUserId) {
        return res.status(400).json({ error: 'Cannot transfer money to yourself' });
    }

    // Verify the sender is the authenticated user
    if (fromUserId !== req.user.id) {
        return res.status(403).json({ error: 'Unauthorized transfer attempt' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Check if sender has sufficient balance
        const senderResult = await client.query(
            'SELECT balance FROM users WHERE id = $1',
            [fromUserId]
        );
        
        if (senderResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Sender not found' });
        }

        const senderBalance = parseFloat(senderResult.rows[0].balance);
        
        if (senderBalance < amount) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        // Check if recipient exists
        const recipientResult = await client.query(
            'SELECT id FROM users WHERE id = $1',
            [toUserId]
        );
        
        if (recipientResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Recipient not found' });
        }

        // Update sender's balance
        await client.query(
            'UPDATE users SET balance = balance - $1 WHERE id = $2',
            [amount, fromUserId]
        );

        // Update recipient's balance
        await client.query(
            'UPDATE users SET balance = balance + $1 WHERE id = $2',
            [amount, toUserId]
        );

        // Create transaction record
        await client.query(
            `INSERT INTO transactions (sender_id, receiver_id, amount, note, status, created_at)
             VALUES ($1, $2, $3, $4, 'completed', CURRENT_TIMESTAMP)`,
            [fromUserId, toUserId, amount, note]
        );

        await client.query('COMMIT');
        console.log('Transfer completed successfully');
        res.json({ message: 'Transfer successful' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Transfer error:', error);
        res.status(500).json({ error: 'Transfer failed', details: error.message });
    } finally {
        client.release();
    }
});

// Create notifications table if it doesn't exist
app.get('/api/setup-notifications', async (req, res) => {
    let client;
    try {
        console.log('Starting notifications table setup...');
        client = await pool.connect();
        
        // First, check if table exists
        const checkResult = await client.query(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'notifications'
            )
        `);
        
        if (checkResult.rows[0].exists) {
            console.log('Dropping existing notifications table...');
            await client.query('DROP TABLE notifications CASCADE');
        }
        
        console.log('Creating notifications table...');
        await client.query(`
            CREATE TABLE notifications (
                id SERIAL PRIMARY KEY,
                sender_id INTEGER REFERENCES users(id) NOT NULL,
                receiver_id INTEGER REFERENCES users(id) NOT NULL,
                message TEXT NOT NULL,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Verify table creation
        const verifyResult = await client.query(`
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'notifications'
        `);
        
        console.log('Table structure:', verifyResult.rows);
        
        client.release();
        res.json({ 
            message: 'Notifications table setup completed',
            table_structure: verifyResult.rows 
        });
    } catch (error) {
        console.error('Error setting up notifications table:', error);
        if (client) client.release();
        res.status(500).json({ 
            error: 'Failed to setup notifications table',
            details: error.message 
        });
    }
});

// Send notification (admin only)
app.post('/api/notifications', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Only admins can send notifications' });
        }

        const { receiver_id, message } = req.body;
        if (!receiver_id || !message) {
            return res.status(400).json({ error: 'Receiver ID and message are required' });
        }

        const client = await pool.connect();
        const result = await client.query(
            'INSERT INTO notifications (sender_id, receiver_id, message) VALUES ($1, $2, $3) RETURNING *',
            [req.user.id, receiver_id, message]
        );
        client.release();

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error sending notification:', error);
        res.status(500).json({ error: 'Failed to send notification' });
    }
});

// Get user's notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const client = await pool.connect();
        const result = await client.query(`
            SELECT n.*, u.name as sender_name 
            FROM notifications n
            JOIN users u ON n.sender_id = u.id
            WHERE n.receiver_id = $1
            ORDER BY n.created_at DESC
        `, [req.user.id]);
        client.release();

        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching notifications:', error);
        res.status(500).json({ error: 'Failed to fetch notifications' });
    }
});

// Mark notification as read
app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
    try {
        const client = await pool.connect();
        const result = await client.query(
            'UPDATE notifications SET is_read = TRUE WHERE id = $1 AND receiver_id = $2 RETURNING *',
            [req.params.id, req.user.id]
        );
        client.release();

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Notification not found' });
        }

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error marking notification as read:', error);
        res.status(500).json({ error: 'Failed to mark notification as read' });
    }
});

// Delete notification
app.delete('/api/notifications/:id', authenticateToken, async (req, res) => {
    let client;
    try {
        client = await pool.connect();
        const result = await client.query(
            'DELETE FROM notifications WHERE id = $1 AND receiver_id = $2 RETURNING *',
            [req.params.id, req.user.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Notification not found' });
        }
        
        res.json({ message: 'Notification deleted successfully' });
    } catch (error) {
        console.error('Error deleting notification:', error);
        res.status(500).json({ error: 'Failed to delete notification' });
    } finally {
        if (client) client.release();
    }
});

// Get all users for recipient dropdown
app.get('/api/recipients', authenticateToken, async (req, res) => {
    let client;
    try {
        console.log('Fetching recipients for user:', req.user.id);
        client = await pool.connect();
        
        // Get all users except the current user
        const result = await client.query(
            'SELECT id, name, email FROM users WHERE id != $1 ORDER BY name',
            [req.user.id]
        );
        
        console.log('Found recipients:', result.rows.length);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching recipients:', error);
        res.status(500).json({ 
            error: 'Failed to fetch recipients',
            details: error.message 
        });
    } finally {
        if (client) {
            client.release();
        }
    }
});

// Delete user account
app.delete('/api/users/me', authenticateToken, async (req, res) => {
    let client;
    try {
        const userId = req.user.id;
        console.log('Starting account deletion process for user:', userId);
        
        if (!userId) {
            console.error('No user ID found in token');
            return res.status(400).json({ error: 'Invalid user ID' });
        }

        client = await pool.connect();
        console.log('Database connection established');

        // First check if user exists
        const userCheck = await client.query('SELECT * FROM users WHERE id = $1', [userId]);
        console.log('User check result:', userCheck.rows);
        
        if (userCheck.rows.length === 0) {
            console.log('User not found:', userId);
            return res.status(404).json({ error: 'User not found' });
        }

        // Start transaction
        await client.query('BEGIN');
        console.log('Transaction started');

        try {
            // Delete transactions
            console.log('Deleting transactions...');
            await client.query(
                'DELETE FROM transactions WHERE sender_id = $1 OR receiver_id = $1',
                [userId]
            );
            console.log('Transactions deleted successfully');

            // Delete notifications
            console.log('Deleting notifications...');
            await client.query(
                'DELETE FROM notifications WHERE user_id = $1',
                [userId]
            );
            console.log('Notifications deleted successfully');

            // Delete user
            console.log('Deleting user...');
            const deleteResult = await client.query(
                'DELETE FROM users WHERE id = $1 RETURNING id',
                [userId]
            );
            console.log('User deletion result:', deleteResult.rows);

            if (deleteResult.rows.length === 0) {
                throw new Error('Failed to delete user');
            }

            // Commit transaction
            await client.query('COMMIT');
            console.log('Transaction committed successfully');

            res.json({ message: 'Account deleted successfully' });
        } catch (error) {
            console.error('Error during deletion process:', error);
            await client.query('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Error in delete account endpoint:', error);
        console.error('Full error details:', {
            message: error.message,
            code: error.code,
            detail: error.detail,
            hint: error.hint,
            where: error.where,
            stack: error.stack
        });

        res.status(500).json({
            error: 'Failed to delete account',
            details: error.message,
            code: error.code
        });
    } finally {
        if (client) {
            try {
                await client.release();
                console.log('Database connection released');
            } catch (releaseError) {
                console.error('Error releasing client:', releaseError);
            }
        }
    }
});

// Change password endpoint
app.post('/api/users/change-password', authenticateToken, async (req, res) => {
    let client;
    try {
        const { currentPassword, newPassword } = req.body;
        
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current password and new password are required' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'New password must be at least 6 characters long' });
        }

        client = await pool.connect();
        
        // Get current user's password hash
        const result = await client.query(
            'SELECT password FROM users WHERE id = $1',
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const currentPasswordHash = result.rows[0].password;
        
        // Verify current password
        const isValidPassword = await bcrypt.compare(currentPassword, currentPasswordHash);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Hash new password
        const newPasswordHash = await bcrypt.hash(newPassword, 10);
        
        // Update password
        await client.query(
            'UPDATE users SET password = $1 WHERE id = $2',
            [newPasswordHash, req.user.id]
        );

        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ error: 'Failed to change password' });
    } finally {
        if (client) {
            client.release();
        }
    }
});

// Password reset endpoints
app.post('/api/users/forgot-password', async (req, res) => {
    let client;
    try {
        const { email } = req.body;
        console.log('Received password reset request for email:', email);
        
        if (!email) {
            console.log('No email provided in request');
            return res.status(400).json({ error: 'Email is required' });
        }

        client = await pool.connect();
        console.log('Database connection established');
        
        // Check if user exists
        const userResult = await client.query(
            'SELECT id, name FROM users WHERE email = $1',
            [email]
        );
        console.log('User lookup result:', userResult.rows.length ? 'User found' : 'User not found');

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = userResult.rows[0];
        console.log('Processing reset request for user:', user.id);
        
        // Generate temporary password
        const tempPassword = crypto.randomBytes(4).toString('hex');
        const hashedPassword = await bcrypt.hash(tempPassword, 10);

        // Update user's password
        await client.query(
            'UPDATE users SET password = $1 WHERE id = $2',
            [hashedPassword, user.id]
        );
        console.log('Temporary password set successfully');

        // Create notification with the temporary password
        await client.query(
            'INSERT INTO notifications (sender_id, receiver_id, message) VALUES ($1, $2, $3)',
            [
                user.id, // sender is the same as receiver in this case
                user.id,
                `Your temporary password is: ${tempPassword}. Please change it after logging in.`
            ]
        );
        console.log('Password reset notification created');

        res.json({ 
            message: 'A temporary password has been sent to your notifications. Please check your notifications page after logging in.'
        });
    } catch (error) {
        console.error('Error in forgot password:', error);
        console.error('Error details:', {
            message: error.message,
            code: error.code,
            detail: error.detail,
            hint: error.hint,
            stack: error.stack
        });
        res.status(500).json({ error: 'Failed to process password reset request' });
    } finally {
        if (client) {
            client.release();
            console.log('Database connection released');
        }
    }
});

app.post('/api/users/reset-password', async (req, res) => {
    let client;
    try {
        const { token, newPassword } = req.body;
        
        if (!token || !newPassword) {
            return res.status(400).json({ error: 'Token and new password are required' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'New password must be at least 6 characters long' });
        }

        client = await pool.connect();
        
        // Find user with valid reset token
        const userResult = await client.query(
            'SELECT id FROM users WHERE reset_token = $1 AND reset_token_expiry > NOW()',
            [token]
        );

        if (userResult.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired reset token' });
        }

        const userId = userResult.rows[0].id;
        
        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        // Update password and clear reset token
        await client.query(
            'UPDATE users SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE id = $2',
            [hashedPassword, userId]
        );

        res.json({ message: 'Password has been reset successfully' });
    } catch (error) {
        console.error('Error in reset password:', error);
        res.status(500).json({ error: 'Failed to reset password' });
    } finally {
        if (client) {
            client.release();
        }
    }
});

// Add profile_picture column to users table
app.get('/api/setup-profile-pictures', async (req, res) => {
    try {
        const client = await pool.connect();
        await client.query(`
            ALTER TABLE users 
            ADD COLUMN IF NOT EXISTS profile_picture TEXT
        `);
        client.release();
        res.json({ message: 'Profile pictures setup completed' });
    } catch (error) {
        console.error('Error setting up profile pictures:', error);
        res.status(500).json({ error: 'Failed to setup profile pictures' });
    }
});

// Profile picture upload endpoint
app.post('/api/users/profile-picture', authenticateToken, async (req, res) => {
    if (!req.files || !req.files.profilePicture) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const profilePicture = req.files.profilePicture;
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    
    if (!allowedTypes.includes(profilePicture.mimetype)) {
        return res.status(400).json({ error: 'Invalid file type. Only JPEG, PNG, and GIF are allowed.' });
    }

    if (profilePicture.size > 5 * 1024 * 1024) { // 5MB limit
        return res.status(400).json({ error: 'File size too large. Maximum size is 5MB.' });
    }

    try {
        const client = await pool.connect();
        
        // Generate unique filename
        const fileExtension = profilePicture.name.split('.').pop();
        const fileName = `${req.user.id}-${Date.now()}.${fileExtension}`;
        const uploadPath = path.join(__dirname, 'uploads', fileName);

        // Create uploads directory if it doesn't exist
        if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
            fs.mkdirSync(path.join(__dirname, 'uploads'));
        }

        // Save the file
        await profilePicture.mv(uploadPath);

        // Update user's profile picture in database
        const profilePictureUrl = `/uploads/${fileName}`;
        await client.query(
            'UPDATE users SET profile_picture = $1 WHERE id = $2',
            [profilePictureUrl, req.user.id]
        );

        client.release();
        res.json({ profilePicture: profilePictureUrl });
    } catch (error) {
        console.error('Error uploading profile picture:', error);
        res.status(500).json({ error: 'Failed to upload profile picture' });
    }
});

// Add a route to serve a default profile picture
app.get('/default-profile-picture', (req, res) => {
  const defaultImagePath = path.join(__dirname, 'uploads', 'default-profile-picture.png');
  if (fs.existsSync(defaultImagePath)) {
    res.sendFile(defaultImagePath);
  } else {
    res.status(404).send('Default profile picture not found');
  }
});

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Serve index.html for the root path
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});