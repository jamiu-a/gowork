require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// ─── Secrets from environment variables (never hardcode these) ───────────────
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-render-dashboard';
const MONGO_URI  = process.env.MONGO_URI;

// ─── Email transporter (Brevo / any SMTP) ────────────────────────────────────
const transporter = nodemailer.createTransport({
    host:   process.env.SMTP_HOST || 'smtp-relay.brevo.com',
    port:   Number(process.env.SMTP_PORT) || 587,
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// ─── Database Schemas ─────────────────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
    username:    { type: String, required: true, unique: true, trim: true },
    email:       { type: String, required: true, unique: true, lowercase: true, trim: true },
    password:    { type: String, required: true },
    role:        { type: String, enum: ['worker', 'client'], required: true },
    resetToken:  { type: String, default: null },
    resetExpiry: { type: Date,   default: null },
    createdAt:   { type: Date,   default: Date.now }
});

const WorkerSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', unique: true, required: true },
    name:   { type: String, required: true },
    title:  { type: String, default: 'Professional Freelancer' },
    skills: [String],
    rate:   { type: Number, default: 0 },
    bio:    { type: String, default: '' }
});

const User   = mongoose.model('User',   UserSchema);
const Worker = mongoose.model('Worker', WorkerSchema);

// ─── Auth Middleware ──────────────────────────────────────────────────────────
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Authorization token missing.' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Session expired or invalid.' });
        req.user = user;
        next();
    });
};

// ─── REGISTER ─────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, role } = req.body;

        if (!username || !email || !password || !role) {
            return res.status(400).json({ error: 'All fields are required.' });
        }

        // Basic email format check
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Please enter a valid email address.' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, email, password: hashedPassword, role });
        await user.save();

        res.status(201).json({ message: 'Account created successfully! You can now log in.' });
    } catch (err) {
        if (err.code === 11000) {
            // Tell the user which field is duplicate
            const field = Object.keys(err.keyPattern)[0];
            const msg = field === 'email' ? 'An account with that email already exists.' : 'That username is already taken.';
            return res.status(400).json({ error: msg });
        }
        res.status(500).json({ error: err.message });
    }
});

// ─── LOGIN ────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Allow login with either username or email
        const user = await User.findOne({
            $or: [{ username }, { email: username }]
        });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: 'Incorrect username or password.' });
        }

        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, role: user.role, username: user.username, email: user.email });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── FORGOT PASSWORD ──────────────────────────────────────────────────────────
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) return res.status(400).json({ error: 'Email is required.' });

        const user = await User.findOne({ email: email.toLowerCase() });

        // Always return the same message so you don't reveal whether an email exists
        const safeMsg = 'If that email is registered, a reset link has been sent.';
        if (!user) return res.json({ message: safeMsg });

        // Generate a secure token
        const token   = crypto.randomBytes(32).toString('hex');
        const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

        user.resetToken  = token;
        user.resetExpiry = expires;
        await user.save();

        const resetLink = `https://gowork-ja.vercel.app/?reset=${token}`;

        await transporter.sendMail({
            from:    `"Go-Work" <${process.env.SMTP_USER}>`,
            to:      user.email,
            subject: 'Reset your Go-Work password',
            html: `
                <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;">
                    <h2 style="color:#1E293B;">Reset your password</h2>
                    <p style="color:#475569;">Click the button below to set a new password. This link expires in 1 hour.</p>
                    <a href="${resetLink}" style="display:inline-block;background:#2563eb;color:white;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:bold;margin:16px 0;">
                        Reset Password
                    </a>
                    <p style="color:#94A3B8;font-size:13px;">If you didn't request this, you can safely ignore this email.</p>
                </div>
            `
        });

        res.json({ message: safeMsg });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── RESET PASSWORD ───────────────────────────────────────────────────────────
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({ error: 'Token and new password are required.' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters.' });
        }

        const user = await User.findOne({
            resetToken:  token,
            resetExpiry: { $gt: new Date() }  // token must not be expired
        });

        if (!user) {
            return res.status(400).json({ error: 'This reset link is invalid or has expired. Please request a new one.' });
        }

        user.password    = await bcrypt.hash(newPassword, 10);
        user.resetToken  = null;
        user.resetExpiry = null;
        await user.save();

        res.json({ message: 'Password updated successfully! You can now log in.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── DELETE ACCOUNT ───────────────────────────────────────────────────────────
app.delete('/api/auth/delete-account', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        await Worker.findOneAndDelete({ userId });
        const deletedUser = await User.findByIdAndDelete(userId);
        if (!deletedUser) return res.status(404).json({ error: 'Account not found.' });
        res.json({ message: 'Your account and all data have been permanently removed from Go-Work.' });
    } catch (err) {
        res.status(500).json({ error: 'Deletion failed: ' + err.message });
    }
});

// ─── WORKER PROFILES ─────────────────────────────────────────────────────────
app.get('/api/workers', async (req, res) => {
    try {
        const { skill, maxRate } = req.query;
        let filters = {};
        if (skill)    filters.skills = { $regex: skill, $options: 'i' };
        if (maxRate)  filters.rate   = { $lte: Number(maxRate) };
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
        const skillsArray = Array.isArray(skills)
            ? skills
            : skills.split(',').map(s => s.trim()).filter(Boolean);

        const worker = await Worker.findOneAndUpdate(
            { userId: req.user.id },
            { name, title, skills: skillsArray, rate: Number(rate), bio },
            { new: true, upsert: true }
        );
        res.json({ message: 'Profile saved!', worker });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── START SERVER ─────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 5000;

mongoose.connect(MONGO_URI)
    .then(() => {
        console.log("Database connected successfully!");
        app.listen(PORT, "0.0.0.0", () => console.log(`Server running safely on port ${PORT}`));
    })
    .catch(err => {
        console.error("CRITICAL DATABASE RUNTIME ERROR:", err.message);
        process.exit(1); // This causes status 1 if the URI breaks or is undefined
    });
