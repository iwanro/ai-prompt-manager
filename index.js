
require('dotenv').config();
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const cors = require('cors');

// Import strategies
const GoogleStrategy = require('passport-google-oauth20').Strategy;
// Add GitHub and Facebook strategies here later

const app = express();
const PORT = process.env.PORT || 3000;

// --- Middleware ---
app.use(cors({
    origin: '*', // IMPORTANT: For production, restrict this to your extension's ID
    credentials: true
}));

app.use(session({
    secret: process.env.SESSION_SECRET, // A random string to sign the session ID cookie
    resave: false,
    saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

// --- Passport Configuration ---

// This saves the user ID to the session
passport.serializeUser((user, done) => {
    done(null, user);
});

// This retrieves the user details from the session
passport.deserializeUser((user, done) => {
    // In a real app, you would fetch user from a database here
    done(null, user);
});

// Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback' // This path must match your setup
  },
  (accessToken, refreshToken, profile, done) => {
    // This function is called after successful authentication
    // Here you would find or create a user in your database
    console.log('Google profile:', profile);
    // For now, we just pass the profile to the next step
    return done(null, profile);
  }
));

// --- Routes ---

// The route that starts the Google login process
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// The callback route that Google redirects to after login
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login-failed' }),
  (req, res) => {
    // Successful authentication!
    // Here you would generate a JWT and send it back to the extension.
    // For now, we'll just send a success message.
    res.send('<h1>Login Successful!</h1><p>You can close this tab.</p>');
  }
);

// A simple route to check if the user is authenticated
app.get('/api/user', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({
            success: true,
            user: {
                name: req.user.displayName,
                photo: req.user.photos[0].value,
                // Add premium status from your database here
                isPremium: false 
            }
        });
    } else {
        res.status(401).json({ success: false, message: 'User not authenticated' });
    }
});

app.get('/', (req, res) => {
    res.send('Backend server is running!');
});


app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
