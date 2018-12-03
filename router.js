const passport = require("passport");

const Authentication = require("./controllers/authentication");
const passportService = require("./services/passport");

const requireAuth = passport.authenticate("jwt", { session: false });
const requireSignin = passport.authenticate("local", { session: false });

module.exports = function(app) {
  app.get("/", requireAuth, function(req, res) {
    return res.send({ hi: "there" });
  });
  app.post("/signin", requireSignin, Authentication.signin);
  // Req = request being received, res = response being sent back, next = mostly for error handling
  app.post("/signup", Authentication.signup);
};
