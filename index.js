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
dotenv.config();

// View engine setup
app.set('views', 'views');
app.engine('handlebars', engine());
app.set('view engine', 'handlebars');
app.use(express.static('public'));
app.use(express.static('images'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

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
  (req, accessToken, refreshToken, profile, cb) => {
    // Defensive check
    if (typeof accessToken !== 'string') {
      console.error('Invalid accessToken type:', typeof accessToken);
      return cb(new Error('accessToken must be a string'));
    }

    // Verify token using Facebook Graph API (appsecret_proof handled by enableProof)
    axios.get(`https://graph.facebook.com/debug_token`, {
      params: {
        input_token: accessToken,
        access_token: `${process.env.FACEBOOK_APP_ID}|${process.env.FACEBOOK_APP_SECRET}`,
      },
    })
      .then(response => {
        if (response.data.data?.is_valid) {
          console.log(profile);
          const user = { name: profile.name, id: profile.id };
          cb(null, user);
        } else {
          cb(null, false, { message: 'Invalid token' });
        }
      })
      .catch(error => cb(error));
  }
));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, { name: user.name, id: user.id });
});

// Auth helpers
const checkAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect('/');
};

const checkLoggedIn = (req, res, next) => {
  if (req.isAuthenticated()) return res.redirect('/content');
  next();
};

// Routes
app.get('/facebook', passport.authenticate('facebook', {
  authType: 'rerequest',
}));

app.get('/auth/facebook',
  passport.authenticate('facebook', {
    failureRedirect: '/',
    successRedirect: '/content',
  })
);

app.get('/', checkLoggedIn, (req, res) => {
  res.render('index');
});

app.get('/content', checkAuthenticated, (req, res) => {
  console.log(req.user);
  res.render('content', {
    name: req.user.name,
    id: req.user.id,
  });
});

app.get('/privacypolicy', (req, res) => res.render('policy'));
app.get('/termsofservice', (req, res) => res.render('terms'));
app.get('/datapolicy', (req, res) => res.render('deletion'));
app.get('/contact', (req, res) => res.render('contact'));

app.post('/logout', (req, res, next) => {
  res.clearCookie('connect.sid');
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(err => {
      if (err) return next(err);
      res.redirect('/');
    });
  });
});

app.post('/seeReactions', (req, res) => {
  res.redirect('/content');
});

// Start server
server.listen(3000, () => {
  console.log('Server running on port 3000');
});