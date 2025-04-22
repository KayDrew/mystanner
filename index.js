const express = require('express');
const app = express();
const dotenv = require('dotenv');
const passport = require('passport');
const FacebookStrategy = require('passport-facebook').Strategy;
const session = require('express-session');
const engine= require('express-handlebars'). engine;
//import { engine } from 'express-handlebars';
const routes = require ('./routes');
const server= require("http").createServer(app);
const cookieParser= require ("cookie-parser");
const axios = require ("axios");
const crypto = require('crypto');
dotenv.config();

// view engine setup
app.set('views', 'views');
app.engine('handlebars', engine());
app.set('view engine', 'handlebars');
app.use(express.static('public'));
app.use(express.static('images'));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));


//app secret proof
function generateAppSecretProof(accessToken, appSecret) {
  return crypto
    .createHmac('sha256', appSecret)
    .update(accessToken)
    .digest('hex');
}



async function fetchUserProfile(accessToken) {
  const appSecretProof = generateAppSecretProof(accessToken, process.env.FACEBOOK_APP_SECRET);

  try {
    const response = await axios.get(`https://graph.facebook.com/v19.0/me`, {
      params: {
        access_token: accessToken,
        appsecret_proof: appSecretProof,
        fields: 'id,name,email', // Request specific fields
      },
    });

    return response.data;
  } catch (error) {
    console.error('Error fetching user profile:', error.response ? error.response.data : error.message);
    throw error;
  }
}


const sessionMiddleware = session({
  secret: process.env.APP_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {maxAge: 60000},
  //cookie: {secure: true}
});

app.use(sessionMiddleware);
// init passport on every route call.
app.use(passport.session()); 


passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: process.env.REDIRECT_URI,
  profileFields: ['id','name'],
  enableProof: true, // Automatically generates appsecret_proof
},
(accessToken, refreshToken, profile, cb) => {
  // Verify the access token with Facebook
  const appSecretProof = generateAppSecretProof(accessToken, process.env.FACEBOOK_APP_SECRET);

  axios.get(`https://graph.facebook.com/debug_token`, {
    params: {
      input_token: accessToken,
      access_token: `${process.env.FACEBOOK_APP_ID}|${process.env.FACEBOOK_APP_SECRET}`,
      appsecret_proof: appSecretProof, // Include appsecret_proof
    },
  })
    .then(response => {
      if (response.data.data.is_valid) {

        console.log(profile);
        let user={name: profile.name, id:profile.id};
          return cb(null, user);

      } else {
        // Token is invalid
        return cb(null, false, { message: 'Invalid token' });
      }
    })
    .catch(error => cb(error));
}));



passport.serializeUser( (user, done) => {
    done(null, user)
    
});

passport.deserializeUser((user, done) => {
      
        done (null, {name: user.name, id: user.id} );
});



let checkAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
 return next();
 }
  res.redirect("/");
}

let checkLoggedIn = (req, res, next) => {
  if (req.isAuthenticated()) { 
       return res.redirect("/content")
   }
  next()
}

 
 app.get('/facebook', passport.authenticate('facebook', { authType: 'reauthenticate'}));

app.get('/facebook/login', 
  passport.authenticate('facebook', {
 failureRedirect: '/', successRedirect:'/content',

 }));

 app.get("/", checkLoggedIn, (req, res) => {
	
  res.render("index");
});

app.get("/content", checkAuthenticated, (req, res) => {
	
	console.log(req.user);
  res.render("content", {
name: req.user.name,
id: req.user.id,
});
});

app.get("/privacypolicy", function(req,res){

res.render("policy");
});

app.get("/termsofservice", function(req,res){

res.render("terms");
});

app.get("/datapolicy", function(req,res){

res.render("deletion");
});

app.get("/contact", function(req,res){

res.render("contact");

});


app.post('/logout', function(req, res, next) {
	
	res.clearCookie('connect.sid');
  req.logout(function(err) {
    if (err) { return next(err); 

}

req.session.destroy( function(err){// destroys session  on both ends
if(err){

return next(err);
}

});
    res.redirect('/');
  });
});

app.post('/seeReactions',function(req,res){

  res.redirect('/content');

});


server.listen(3000,()=>{
console.log("running on port 3000");
});



//security 





