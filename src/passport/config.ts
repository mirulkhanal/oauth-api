import passport from 'passport';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import passportLocal from 'passport-local';
import GoogleStrategy from 'passport-google-oauth20';
import GitHubStrategy from 'passport-github2';
import FacebookStrategy from 'passport-facebook';
import { generateJWT } from '../utils/helpers';

const prisma = new PrismaClient();
const LocalStrategy = passportLocal.Strategy;

// Passport Serialize/Deserialize
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id: number, done) => {
  const user = await prisma.user.findUnique({ where: { id } });
  done(null, user);
});

// -------------------- Local Strategy --------------------
passport.use(
  new LocalStrategy(
    { usernameField: 'email' },
    async (email: string, password: string, done) => {
      const user = await prisma.user.findUnique({ where: { email } });
      if (
        !user ||
        !user.password ||
        !(await bcrypt.compare(password, user.password))
      ) {
        return done(null, false, { message: 'Invalid credentials' });
      }
      return done(null, user);
    }
  )
);

// -------------------- Google Strategy --------------------
passport.use(
  new GoogleStrategy.Strategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: '/auth/google/callback',
    },
    async (accessToken: any, refreshToken: any, profile, done) => {
      const { id, displayName, emails, photos } = profile;
      const email = emails?.[0].value;
      const picture = photos?.[0].value;

      let user = await prisma.user.findUnique({ where: { googleId: id } });
      if (!user) {
        user = await prisma.user.create({
          data: {
            googleId: id,
            email: email!,
            name: displayName,
            profilePicture: picture,
          },
        });
      }
      return done(null, user);
    }
  )
);

// -------------------- GitHub Strategy --------------------
passport.use(
  new GitHubStrategy.Strategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
      callbackURL: '/auth/github/callback',
    },
    async (accessToken: any, refreshToken: any, profile: any, done: any) => {
      const { id, username, emails, photos } = profile;
      const email = emails?.[0].value;

      let user = await prisma.user.findUnique({ where: { githubId: id } });
      if (!user) {
        user = await prisma.user.create({
          data: {
            githubId: id,
            email: email!,
            name: username,
            profilePicture: photos?.[0]?.value,
          },
        });
      }
      return done(null, user);
    }
  )
);

// -------------------- Facebook Strategy --------------------
passport.use(
  new FacebookStrategy.Strategy(
    {
      clientID: process.env.FACEBOOK_CLIENT_ID!,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET!,
      callbackURL: '/auth/facebook/callback',
      profileFields: ['id', 'displayName', 'email', 'photos'],
    },
    async (accessToken, refreshToken, profile, done) => {
      const { id, displayName, emails, photos } = profile;
      const email = emails?.[0].value;

      let user = await prisma.user.findUnique({ where: { facebookId: id } });
      if (!user) {
        user = await prisma.user.create({
          data: {
            facebookId: id,
            email: email!,
            name: displayName,
            profilePicture: photos?.[0]?.value,
          },
        });
      }
      return done(null, user);
    }
  )
);

export default passport;
