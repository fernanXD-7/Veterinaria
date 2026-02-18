// Import modules
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');


// Load environment variables
dotenv.config();

// Create Express app
const app = express();
app.use(express.json()); // Parse JSON requests
app.use(cors()); // Enable CORS for frontend

// Middleware para verificar token JWT en rutas protegidas
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user; // Guardamos los datos del usuario
    next();
  });
};

// MySQL Connection Setup
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

// Connect to MySQL and handle errors
db.connect((err) => {
  if (err) {
    console.error('MySQL Connection Error:', err);
    throw err; // Stop if connection fails
  }
  console.log('Connected to MySQL successfully!');
});

// Create 'users' table if it doesn't exist (run once)
db.query(`
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
  )
`, (err) => {
  if (err) console.error('Table Creation Error:', err);
});

// API Endpoint: Register a new user (for testing)
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('Missing username or password');

  try {
    const hashedPassword = await bcrypt.hash(password, 10); // Hash password
    db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).send('Username already exists');
        return res.status(500).send('Server error');
      }
      res.status(201).send('User registered successfully');
    });
  } catch (error) {
    res.status(500).send('Hashing error');
  }
});

// API Endpoint: Login (devuelve JWT)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });

  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (results.length === 0) return res.status(401).json({ error: 'Invalid username or password' });

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid username or password' });

    // Generar token JWT
    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Respuesta con token y datos del usuario
    res.json({
      success: true,
      token: token,
      user: {
        id: user.id,
        username: user.username
      }
    });
  });
});

// Endpoint protegido: obtener datos del usuario logueado
app.get('/api/me', authenticateToken, (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username,
    message: 'Datos del usuario autenticado correctamente'
  });
});

// Start the server
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Backend server running on http://localhost:${port}`);
});