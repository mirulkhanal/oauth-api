import bcrypt from 'bcryptjs';
import express from 'express';
import passport from 'passport';
import { PrismaClient } from '@prisma/client';
import { generateJWT } from '../utils/helpers';

const router = express.Router();
const prisma = new PrismaClient();

// -------------------- Local Signup --------------------
router.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { name, email, password: hashedPassword },
    });
    res
      .status(201)
      .json({ message: 'User registered', token: generateJWT(user), user });
  } catch (error) {
    res.status(500).json({ error: 'User registration failed' });
  }
});

// -------------------- Local Login --------------------
router.post('/login', passport.authenticate('local'), (req, res) => {
  const token = generateJWT(req.user);
  res.json({ message: 'Login successful', token, user: req.user });
});

// -------------------- Google OAuth --------------------
router.get(
  '/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);
router.get('/google/callback', passport.authenticate('google'), (req, res) => {
  const token = generateJWT(req.user);
  res.redirect(`/success?token=${token}`);
});

// -------------------- GitHub OAuth --------------------
router.get(
  '/github',
  passport.authenticate('github', { scope: ['user:email'] })
);
router.get('/github/callback', passport.authenticate('github'), (req, res) => {
  const token = generateJWT(req.user);
  res.redirect(`/success?token=${token}`);
});

// -------------------- Facebook OAuth --------------------
router.get(
  '/facebook',
  passport.authenticate('facebook', { scope: ['email'] })
);
router.get(
  '/facebook/callback',
  passport.authenticate('facebook'),
  (req, res) => {
    const token = generateJWT(req.user);
    res.redirect(`/success?token=${token}`);
  }
);

export default router;
