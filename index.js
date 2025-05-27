const express = require('express');
const app = express();
const dotenv = require('dotenv');
const passport = require('passport');
const FacebookStrategy = require('passport-facebook').Strategy;
const session = require('express-session');
const { engine } = require('express-handlebars');
const server = require('http').createServer(app);
const cookieParser = require('cookie-parser');
const axios = require('axios');
const crypto = require('crypto');
const helmet = require('helmet');
dotenv.config();

// View engine setup
app.set('views', 'views');
app.engine('handlebars', engine());
app.set('view engine', 'handlebars');
app.use(express.static('public'));
app.use(express.static('images'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Security Middleware (Helmet)
app.use(helmet.crossOriginResourcePolicy({ policy: 'cross-origin' }));
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
app.use(helmet.noSniff());
app.use(helmet.frameguard({ action: 'sameorigin' }));
app.use(helmet.permittedCrossDomainPolicies({ permittedPolicies: 'none' }));

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "https://www.facebook.com",
        "https://static.xx.fbcdn.net",
        "https://graph.facebook.com",
        "https://*.facebook.com",
        "https://*.fbcdn.net",
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://www.facebook.com",
        "https://static.xx.fbcdn.net",
        "https://*.facebook.com",
        "https://*.fbcdn.net",
        "https://fonts.googleapis.com",    // Added for Google Fonts CSS
        "https://cdnjs.cloudflare.com",    // Added for Font Awesome CSS
      ],
      fontSrc: [                           // Added for Font Awesome and Google Fonts
        "'self'",
        "https://fonts.gstatic.com",       // For Google Fonts actual font files
        "https://cdnjs.cloudflare.com",    // For Font Awesome font files
      ],
      imgSrc: [
        "'self'",
        "data:",
        "https://www.facebook.com",
        "https://static.xx.fbcdn.net",
        "https://*.facebook.com",
        "https://*.fbcdn.net",
      ],
      connectSrc: [
        "'self'",
        "https://connect.facebook.net",
        "https://www.facebook.com",
        "https://graph.facebook.com",
        "https://*.facebook.com",
        "https://*.fbcdn.net",
      ],
      frameSrc: [
        "'self'",
        "https://www.facebook.com",
        "https://static.xx.fbcdn.net",
        "https://*.facebook.com",
        "https://*.fbcdn.net",
      ],
      formAction: [
        "'self'",
        "https://www.facebook.com",
        "https://*.facebook.com",
      ],
      frameAncestors: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      upgradeInsecureRequests: [],
    },
  })
);

// Optional: Generate appsecret_proof (for manual use)
function generateAppSecretProof(accessToken, appSecret) {
  return crypto
    .createHmac('sha256', appSecret)
    .update(accessToken)
    .digest('hex');
}

// Optional: Used outside the strategy to fetch extra profile info
async function fetchUserProfile(accessToken) {
  const appSecretProof = generateAppSecretProof(accessToken, process.env.FACEBOOK_APP_SECRET);
  try {
    const response = await axios.get(`https://graph.facebook.com/v19.0/me`, {
      params: {
        access_token: accessToken,
        appsecret_proof: appSecretProof,
        fields: 'id,name,email',
      },
    });
    return response.data;
  } catch (error) {
    console.error('Error fetching user profile:', error.response?.data || error.message);
    throw error;
  }
}

// Session setup
const sessionMiddleware = session({
  secret: process.env.APP_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 60000 },
});

app.use(cookieParser());
app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

// Passport Facebook strategy
passport.use(new FacebookStrategy(
  {
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: process.env.REDIRECT_URI,
    profileFields: ['id', 'name'],
    enableProof: true, // Automatically generates appsecret_proof
    passReqToCallback: true,
    authType: 'reauthenticate',
    state: true,
  },
  async (req, accessToken, refreshToken, profile, cb) => {
    if (typeof accessToken !== 'string') {
      return cb(new Error('Invalid accessToken type'));
    }

    try {
      const { data } = await axios.get('https://graph.facebook.com/debug_token', {
        params: {
          input_token: accessToken,
          access_token: `${process.env.FACEBOOK_APP_ID}|${process.env.FACEBOOK_APP_SECRET}`,
        },
      });

      if (data?.data?.is_valid) {
        const user = { name: profile.name, id: profile.id };
        cb(null, user);
      } else {
        cb(null, false, { message: 'Invalid token' });
      }
    } catch (err) {
      cb(err);
    }
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Utility for Facebook appsecret_proof
// (Note: This function is duplicated, consider removing one if not used elsewhere)
function generateAppSecretProof(token, secret) {
  return crypto.createHmac('sha256', secret).update(token).digest('hex');
}

// Utility to fetch user profile (Note: This function is duplicated, consider removing one if not used elsewhere)
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

// Auth middleware
const checkAuthenticated = (req, res, next) => {
  req.isAuthenticated() ? next() : res.redirect('/');
};
const checkLoggedIn = (req, res, next) => {
  req.isAuthenticated() ? res.redirect('/content') : next();
};

// Routes
app.get('/', checkLoggedIn, (req, res) => res.render('index'));
app.get('/content', checkAuthenticated, (req, res) => {
  res.render('content', { name: req.user.name, id: req.user.id });
});
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

app.get('/account-deletion-status', (req, res) => {
  const confirmationCode = req.query.code || 'N/A';
  res.render('deletionstatus', { code: confirmationCode });
});

app.get('/goodbye', (req, res) => {
  res.render('goodbye');
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

app.post('/seeReactions', (req, res) => {
  res.redirect('/content');
});

// Facebook Data Deletion Callback
function parseSignedRequest(signedRequest, secret) {
  const [encodedSig, payload] = signedRequest.split('.');
  const data = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));

  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  if (expectedSig !== encodedSig) {
    throw new Error('Invalid signature');
  }
  return data;
}

app.post('/facebook-data-deletion', (req, res) => {
  try {
    const data = parseSignedRequest(req.body.signed_request, process.env.FACEBOOK_APP_SECRET);

    // Generate a unique confirmation code
    const confirmationCode = crypto.randomBytes(16).toString('hex');

    // Log the user ID requesting deletion
    console.log('Data deletion request received for user ID:', data.user_id);

    // Construct a compliant deletion status URL
    const statusUrl = `https://mystanner.onrender.com/account-deletion-status?code=${confirmationCode}`;

    // Respond in Meta's required format
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
