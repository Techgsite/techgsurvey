// Node.js/Express backend for email verification and password reset (best practice, uses MongoDB and Nodemailer)
const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect('mongodb://localhost:27017/techg', { useNewUrlParser: true, useUnifiedTopology: true });
const userSchema = new mongoose.Schema({
  email: String,
  username: String,
  password: String,
  isVerified: { type: Boolean, default: false },
  verifyToken: String,
  resetToken: String,
  resetTokenExp: Date
});
const User = mongoose.model('User', userSchema);

const transporter = nodemailer.createTransport({
  service: 'gmail', // or your SMTP provider
  auth: {
    user: 'your_gmail@gmail.com', // replace with your email
    pass: 'your_app_password' // use app password for Gmail
  }
});

// Signup endpoint
app.post('/api/signup', async (req, res) => {
  const { email, username, password } = req.body;
  if(await User.findOne({ email })) return res.status(400).json({ message: 'Email already exists.' });
  const verifyToken = crypto.randomBytes(32).toString('hex');
  const user = new User({ email, username, password, verifyToken });
  await user.save();
  const link = `http://localhost:3000/api/verify-email?token=${verifyToken}`;
  await transporter.sendMail({
    to: email,
    subject: 'Verify your email',
    html: `<p>Click <a href="${link}">here</a> to verify your email.</p>`
  });
  res.json({ message: 'Signup successful. Please check your email to verify.' });
});

// Email verification endpoint
app.get('/api/verify-email', async (req, res) => {
  const { token } = req.query;
  const user = await User.findOne({ verifyToken: token });
  if(!user) return res.status(400).send('Invalid or expired token.');
  user.isVerified = true;
  user.verifyToken = undefined;
  await user.save();
  res.send('Email verified! You can now log in.');
});

// Forgot password endpoint
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if(!user) return res.json({ message: 'If your email exists, a reset link has been sent.' });
  const resetToken = crypto.randomBytes(32).toString('hex');
  user.resetToken = resetToken;
  user.resetTokenExp = new Date(Date.now() + 3600*1000); // 1 hour
  await user.save();
  const link = `http://localhost:3000/reset-password.html?token=${resetToken}`;
  await transporter.sendMail({
    to: email,
    subject: 'Reset your password',
    html: `<p>Click <a href="${link}">here</a> to reset your password.</p>`
  });
  res.json({ message: 'If your email exists, a reset link has been sent.' });
});

// Reset password endpoint
app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;
  const user = await User.findOne({ resetToken: token, resetTokenExp: { $gt: new Date() } });
  if(!user) return res.status(400).json({ message: 'Invalid or expired token.' });
  user.password = password;
  user.resetToken = undefined;
  user.resetTokenExp = undefined;
  await user.save();
  res.json({ message: 'Password reset successful.' });
});

app.listen(3000, () => console.log('Backend running on http://localhost:3000'));
