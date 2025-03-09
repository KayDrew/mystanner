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
dotenv.config();

// view engine setup
app.set('views', 'views');
app.engine('handlebars', engine());
app.set('view engine', 'handlebars');
app.use(express.static('public'));
app.use(express.static('images'));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));


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
    clientID:process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "/facebook/login",
  },
  function(accessToken, refreshToken, profile, cb) {
    
    console.log(profile.displayName);
    let user={name: profile.displayName, id:profile.id};
      return cb(null, user);
    
  }
));


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




server.listen(3000,()=>{
console.log("running on port 3000");
});