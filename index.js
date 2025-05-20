const express = require('express');
const dotenv = require('dotenv');
const passport = require('passport');
const FacebookStrategy = require('passport-facebook').Strategy;
const session = require('express-session');
const { engine } = require('express-handlebars');
const http = require('http');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const crypto = require('crypto');
const helmet = require('helmet');
const compression = require('compression');

dotenv.config();

const app = express();
const server = http.createServer(app);

// View engine setup
app.set('views', 'views');
app.engine('handlebars', engine());
app.set('view engine', 'handlebars');

// Static files
app.use(express.static('public'));
app.use(express.static('images'));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(compression());

// Security headers

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'", 'https://www.facebook.com'],
    scriptSrc: ["'self'", 'https://*.facebook.net', 'https://*.googleapis.com', 'https://*.cloudflare.com'],
    connectSrc: ["'self'", 'https://graph.facebook.com'],
    frameSrc: ['https://www.facebook.com'],
    imgSrc: ["'self'", 'data:', 'https://*.facebook.com'],
    styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    fontSrc: ["'self'", 'https://fonts.gstatic.com'],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: [],
  },
}));

app.use(helmet.crossOriginResourcePolicy({ policy: 'same-origin' }));
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
app.use(helmet.noSniff());
app.use(helmet.frameguard({ action: 'sameorigin' }));
app.use(helmet.permittedCrossDomainPolicies({ permittedPolicies: 'none' }));

// Session
app.use(session({
  secret: process.env.APP_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1800000 },
}));

// Passport
app.use(passport.initialize());
app.use(passport.session());

passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: process.env.REDIRECT_URI,
  profileFields: ['id', 'name'],
  enableProof: true,
  passReqToCallback: true,
  authType: 'reauthenticate',
  state: true,
}, async (req, accessToken, _, profile, done) => {
  try {
    const { data } = await axios.get('https://graph.facebook.com/debug_token', {
      params: {
        input_token: accessToken,
        access_token: `${process.env.FACEBOOK_APP_ID}|${process.env.FACEBOOK_APP_SECRET}`,
      },
    });

    if (data?.data?.is_valid) {
      return done(null, { name: profile.name, id: profile.id });
    } else {
      return done(null, false, { message: 'Invalid token' });
    }
  } catch (error) {
    return done(error);
  }
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Utility functions
function generateAppSecretProof(token, secret) {
  return crypto.createHmac('sha256', secret).update(token).digest('hex');
}

async function fetchUserProfile(accessToken) {
  const proof = generateAppSecretProof(accessToken, process.env.FACEBOOK_APP_SECRET);
  try {
    const { data } = await axios.get('https://graph.facebook.com/v19.0/me', {
      params: {
        access_token: accessToken,
        appsecret_proof: proof,
        fields: 'id,name,email',
      },
    });
    return data;
  } catch (error) {
    console.error('Fetch user profile error:', error.message);
    throw error;
  }
}

function parseSignedRequest(signedRequest, secret) {
  const [encodedSig, payload] = signedRequest.split('.');
  const data = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
  const expectedSig = crypto.createHmac('sha256', secret)
    .update(payload)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  if (expectedSig !== encodedSig) throw new Error('Invalid signature');
  return data;
}

// Auth middleware
const checkAuthenticated = (req, res, next) => req.isAuthenticated() ? next() : res.redirect('/');
const checkLoggedIn = (req, res, next) => req.isAuthenticated() ? res.redirect('/content') : next();

// Routes
app.get('/', checkLoggedIn, (req, res) => res.render('index'));
app.get('/content', checkAuthenticated, (req, res) => res.render('content', req.user));
app.get('/facebook', passport.authenticate('facebook', { authType: 'rerequest' }));
app.get('/auth/facebook',
  passport.authenticate('facebook', {
    failureRedirect: '/',
    successRedirect: '/content',
  })
);

app.get('/privacypolicy', (req, res) => res.render('policy'));
app.get('/termsofservice', (req, res) => res.render('terms'));
app.get('/datadeletionpolicy', (req, res) => res.render('deletion'));
app.get('/contact', (req, res) => res.render('contact'));
app.get('/goodbye', (req, res) => res.render('goodbye'));

app.get('/account-deletion-status', (req, res) => {
  res.render('deletionstatus', { code: req.query.code || 'N/A' });
});

app.post('/logout', (req, res, next) => {
  res.clearCookie('connect.sid');
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(err => {
      if (err) return next(err);
      res.redirect('/goodbye');
    });
  });
});

app.post('/seeReactions', (req, res) => res.redirect('/content'));

// Facebook data deletion callback
app.post('/facebook-data-deletion', (req, res) => {
  try {
    const data = parseSignedRequest(req.body.signed_request, process.env.FACEBOOK_APP_SECRET);
    const confirmationCode = crypto.randomBytes(16).toString('hex');
    const statusUrl = `https://mystanner.onrender.com/account-deletion-status?code=${confirmationCode}`;

    console.log('Data deletion request for user ID:', data.user_id);

    res.json({
      url: statusUrl,
      confirmation_code: confirmationCode
    });
  } catch (error) {
    console.error('Data deletion error:', error.message);
    res.status(400).json({ error: 'Invalid signed request' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));