const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const axios = require('axios');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'tasknaija-secret-123';
const PORT = process.env.PORT || 3000;

const db = new sqlite3.Database('./tasknaija.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT,
    description TEXT,
    category TEXT,
    price REAL,
    location TEXT,
    status TEXT DEFAULT 'open',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Health check - Render go use this
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'TaskNaija Backend is Live!' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Auth middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  const hashed = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (name, email, password) VALUES (?,?,?)', [name, email, hashed], function(err) {
    if (err) return res.status(400).json({ error: 'Email already exists' });
    const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET);
    res.json({ token, user: { id: this.lastID, name, email } });
  });
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (!user) return res.status(400).json({ error: 'User not found' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Wrong password' });
    const token = jwt.sign({ id: user.id, email }, JWT_SECRET);
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  });
});

// Get all tasks
app.get('/api/tasks', (req, res) => {
  db.all('SELECT * FROM tasks ORDER BY created_at DESC', [], (err, rows) => {
    res.json(rows || []);
  });
});

// Create task
app.post('/api/tasks', auth, (req, res) => {
  const { title, description, category, price, location } = req.body;
  db.run('INSERT INTO tasks (user_id, title, description, category, price, location) VALUES (?,?,?,?,?,?)',
    [req.user.id, title, description, category, price, location], function(err) {
    if
