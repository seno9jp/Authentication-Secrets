require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

const userScheme = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: Array
});

userScheme.plugin(passportLocalMongoose);
userScheme.plugin(findOrCreate);

const User = new mongoose.model("User", userScheme);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, {
            id: user.id,
            username: user.username,
            picture: user.picture
        });
    });
});

passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets"
    },
    function(accessToken, refreshToken, profile, cb) {
        console.log(profile);

        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", function (req, res) {
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function(req, res) {
        res.redirect('/secrets');
    });

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/secrets", function (req, res) {
    if (req.isAuthenticated()) {
        User.find({"secret": {$ne: null}}, function (err, foundUsers) {
            if (err) {
                console.log(err);
            } else {
                if (foundUsers) {
                    res.render("secrets", {usersWithSecrets: foundUsers});
                }
            }
        });
    } else {
        res.redirect("/login");
    }
    // res.set(
    //     'Cache-Control',
    //     'no-cache, private, no-store, must-revalidate, max-stal e=0, post-check=0, pre-check=0'
    // );
    // if (req.isAuthenticated()) {
    //     res.render("secrets");
    // } else {
    //     res.redirect("/login");
    // }
});

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        User.findById(req.user.id,function (err,foundUser){
            if(!err){
                res.render("submit",{secrets:foundUser.secret});
            }
        });
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        User.findById(req.user.id, function (err,foundUser) {
            foundUser.secret.push(req.body.secret);
            foundUser.save(function () {
                res.redirect("/secrets");
            });
        });
    } else {
        res.redirect("/login");
    }
});

app.post("/submit/delete",function (req, res){
    if(req.isAuthenticated()){
        User.findById(req.user.id, function (err, foundUser){
            foundUser.secret.splice(foundUser.secret.indexOf(req.body.secret),1);
            foundUser.save(function (err) {
                if(!err){
                    res.redirect("/secrets");
                }
            });
        });
    }else {
        res.redirect("/login");
    }
});

app.get("/logout", function (req, res, next) {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect("/");
    });
});


app.post("/register", function (req, res) {

    User.register({username: req.body.username}, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", function (req, res) {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});






app.listen(3000, function () {
    console.log("Server started on port 3000.")
})