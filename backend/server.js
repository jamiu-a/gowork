const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = 'super_secure_marketplace_secret_key_2026';

// Database Models
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['worker', 'client'], required: true }
});

const WorkerSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', unique: true, required: true },
    name: { type: String, required: true },
    title: { type: String, default: 'Professional Freelancer' },
    skills: [String],
    rate: { type: Number, default: 0 },
    bio: { type: String, default: '' }
});

const User = mongoose.model('User', UserSchema);
const Worker = mongoose.model('Worker', WorkerSchema);

// Token Verification Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: "Authorization token missing." });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Session expired or invalid." });
        req.user = user;
        next();
    });
};

// Authentication Endpoints
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, role } = req.body;
        if (!username || !password || !role) {
            return res.status(400).json({ error: "All fields are required." });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword, role });
        await user.save();
        res.status(201).json({ message: "Account created successfully! You can now log in." });
    } catch (err) {
        res.status(500).json({ error: err.code === 11000 ? "Username is already taken." : err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: "Invalid credentials matched." });
        }
        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, role: user.role, username: user.username });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Freelancer Profile Management Endpoints
app.get('/api/workers', async (req, res) => {
    try {
        const { skill, maxRate } = req.query;
        let filters = {};
        if (skill) filters.skills = { $regex: skill, $options: 'i' };
        if (maxRate) filters.rate = { $lte: Number(maxRate) };
        
        const workers = await Worker.find(filters);
        res.json(workers);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/workers/me', authenticateToken, async (req, res) => {
    try {
        const worker = await Worker.findOne({ userId: req.user.id });
        if (!worker) return res.json({ profileMissing: true });
        res.json(worker);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/workers', authenticateToken, async (req, res) => {
    try {
        const { name, title, skills, rate, bio } = req.body;
        const skillsArray = Array.isArray(skills) ? skills : skills.split(',').map(s => s.trim()).filter(s => s);

        const worker = await Worker.findOneAndUpdate(
            { userId: req.user.id },
            { name, title, skills: skillsArray, rate: Number(rate), bio },
            { new: true, upsert: true }
        );
        res.status(200).json({ message: "Profile saved securely!", worker });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Production Startup Connection
const PORT = process.env.PORT || 5000;
mongoose.connect('mongodb+srv://goworkuser:GoWorkPass2026@cluster0.5j9esgc.mongodb.net/gowork?retryWrites=true&w=majority')
    .then(() => app.listen(PORT, "0.0.0.0", () => console.log(`Server configuration running on port ${PORT}`)))
    .catch(err => console.error("Database connection fault:", err));
