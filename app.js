//jshint esversion:6
//a ordem das coisas com session e passport geralmente vai fazer diferença
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//a ordem aki em baixo vai fazer a diferença
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

//a ordem aki faz diferença tb (eu acho)
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
//passport managing sessions
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

//local login strategy
passport.use(User.createStrategy());
//coisas com cookies ai (level 5)
passport.serializeUser(function(user, done){
  done(null, user.id);
});
passport.deserializeUser(function(id, done){
  User.findById(id, function(err, user){
    done(err, user);
  });
});

//google authentication
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) { //posso fazer pegar com mongoose-findorcreate package
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", {scope: ["profile"]})
);

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", (req, res) => {
  User.find({"secret": {$ne: null}}, (err, foundUsers) => {
    if(err){
      console.log(err);
    } else{
      if(foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", (req, res) => {
  //para n precisar fazer ficar fazendo login o tempo todo
  //toda vez que o server reinicializa, os cookies são deletados
  //ai tem que fazer login dnv de qualquer forma
  if(req.isAuthenticated()){
    res.render("submit");
  } else{
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.logout(); //simples assim :D
  res.redirect("/");
});

app.post("/register", (req, res) => {

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register"); //try again
    } else{
      //manda uns cookies ai
      passport.authenticate("local")(req, res, function(){ //isso aki ta meio estranho ;-; (a gramática do código no caso, o que ele faz eu entendi)
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/login", (req, res) => {

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){//passport method
    if(err){
      console.log(err);
      res.redirect("/login"); //try again
    } else{
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, (err, foundUser) => {
    if(err){
      console.log(err);
    } else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.listen(3000, function() {
  console.log("Server started on port 3000!");
});
