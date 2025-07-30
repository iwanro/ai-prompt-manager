
require('dotenv').config();
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const cors = require('cors');
const fs = require('fs');
const bodyParser = require('body-parser');

// Import strategies
const GoogleStrategy = require('passport-google-oauth20').Strategy;
// Add GitHub and Facebook strategies here later

const app = express();
app.set('trust proxy', 1); // Trust the first proxy
const PORT = process.env.PORT || 3000;

// --- Database ---
let db = { users: [] };
const DB_PATH = './db.json';

// Load the database
try {
    const data = fs.readFileSync(DB_PATH, 'utf8');
    db = JSON.parse(data);
} catch (err) {
    if (err.code === 'ENOENT') {
        console.log('db.json not found, creating a new one.');
        fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
    } else {
        console.error('Error reading db.json:', err);
    }
}

// Function to save the database
const saveDB = () => {
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
};


// --- Middleware ---
const allowedOrigins = [
    'https://ai-prompt-manager-api.onrender.com',
    // TODO: Add your Chrome Extension ID here later
    // 'chrome-extension://<your-extension-id>'
];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);

        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true
}));
app.use(bodyParser.json());
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
    done(null, user.id);
});

// This retrieves the user details from the session
passport.deserializeUser((id, done) => {
    const user = db.users.find(u => u.id === id);
    done(null, user);
});

// Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
    secure: true // Force HTTPS for callback URL
  },
  (accessToken, refreshToken, profile, done) => {
    // Find or create user in the database
    let user = db.users.find(u => u.id === profile.id);

    if (user) {
        // Update user profile information
        user.displayName = profile.displayName;
        user.photos = profile.photos;
    } else {
        // Create a new user
        user = {
            id: profile.id,
            displayName: profile.displayName,
            emails: profile.emails,
            photos: profile.photos,
            isPremium: false // Default to non-premium
        };
        db.users.push(user);
    }
    
    saveDB();
    return done(null, user);
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
                isPremium: req.user.isPremium
            }
        });
    } else {
        res.status(401).json({ success: false, message: 'User not authenticated' });
    }
});

// Route to grant premium access (for internal use)
app.post('/api/set-premium', (req, res) => {
    const { userId } = req.body;
    const user = db.users.find(u => u.id === userId);

    if (user) {
        user.isPremium = true;
        saveDB();
        res.json({ success: true, message: `User ${user.displayName} is now premium.` });
    } else {
        res.status(404).json({ success: false, message: 'User not found.' });
    }
});


app.get('/', (req, res) => {
    res.send('Backend server is running!');
});


app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
