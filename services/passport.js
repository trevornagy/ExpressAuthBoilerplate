const passport = require("passport");

const User = require("../models/user");
const config = require("../config");

const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const LocalStrategy = require("passport-local");

// Create local strategy
const localLogin = new LocalStrategy({ usernameField: "email" }, function(
  email,
  password,
  done
) {
  // Verify this email/pass, call done with the user
  // If it is the correct email/pass
  // Otherwise, call done with false
  User.findOne({ email: email }, function(err, user) {
    if (err) {
      return done(err);
    }
    if (!user) {
      return done(null, false);
    }

    // compare passwords, is password equal to user password
    user.comparePassword(password, function(err, isMatch) {
      if (err) {
        return done(err);
      }

      if (!isMatch) {
        return done(null, false);
      }

      return done(null, user);
    });
  });
});

// Setup options for JWT strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader("authorization"),
  secretOrKey: config.secret
};

// Create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  // See if the user id in the payload exists in our db
  // If it does, call 'done' with that other
  // Otherwise, call done without a user object
  User.findById(payload.sub, function(err, user) {
    if (err) {
      return done(err, false);
    }

    if (user) {
      done(null, user);
    } else {
      done(null, false);
    }
  });
});

// Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);
