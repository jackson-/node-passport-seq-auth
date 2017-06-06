var bCrypt = require('bcrypt-nodejs');
var OAuth2Strategy = require('passport-oauth2');

module.exports = function(passport, user) {
    var User = user;
    var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.linkedin.com/oauth/v2/authorization',
        tokenURL: 'https://www.linkedin.com/oauth/v2/accessToken',
        clientID: '77ii2o706eetms',
        clientSecret: 'tjkTez60kDypOegv',
        callbackURL: "http://localhost:5000/api/auth/linkedin/callback",
      },
      function(accessToken, refreshToken, profile, cb) {
        console.log("EMAIL", profile.emailAddress)
        User.find({where: {email: profile.emailAddress}}
        , function (err, user) {
          console.log("ERR", err, "USER", user)
          return cb(err, user);
        });
      })

    strategy.userProfile = function (accesstoken, done) {
      console.log("BEFORE")
      // choose your own adventure, or use the Strategy's oauth client
      this._oauth2._request("GET", `https://api.linkedin.com/v1/people/~:(id,first-name,last-name,public-profile-url,picture-urls::(original),positions:(title,company),email-address)?oauth2_access_token=${accesstoken}&format=json`, null, null, accesstoken, (err, data) => {
        if (err) { console.log("ERR", err); return done(err); }
        try {
            console.log("DATA INSIDE", data)
            data = JSON.parse( data );
        }
        catch(e) {
          console.log("E", e)
          return done(e);
        }
        console.log("DATA", data)
        done(null, data);
      });
    };
    passport.use(strategy);

    var LocalStrategy = require('passport-local').Strategy;

    passport.use('local-signin', new LocalStrategy({
            // by default, local strategy uses username and password, we will override with email
            usernameField: 'email',
            passwordField: 'password',
            passReqToCallback: true // allows us to pass back the entire request to the callback
        },
        function(req, email, password, done) {
            var User = user;
            var isValidPassword = function(userpass, password) {
                return bCrypt.compareSync(password, userpass);
            }
            User.findOne({
                where: {
                    email: email
                }
            }).then(function(user) {
                if (!user) {
                    return done(null, false, {
                        message: 'Email does not exist'
                    });
                }
                if (!isValidPassword(user.password, password)) {
                    return done(null, false, {
                        message: 'Incorrect password.'
                    });
                }
                var userinfo = user.get();
                return done(null, userinfo);
            }).catch(function(err) {
                console.log("Error:", err);
                return done(null, false, {
                    message: 'Something went wrong with your Signin'
                });
            });
        }
    ));

    passport.use('local-signup', new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true // allows us to pass back the entire request to the callback

    },(req, email, password, done) => {
      var generateHash = function(password) {
        return bCrypt.hashSync(password, bCrypt.genSaltSync(8), null);
      };
      console.log()
      User.findOne({
          where: {
              email: email
          }
      }).then(function(user) {
          if (user){
              return done(null, false, {
                  message: 'That email is already taken'
              });
          } else {
              var userPassword = generateHash(password);
              var data = {
                      email: email,
                      password: userPassword,
                      firstname: req.body.firstname,
                      lastname: req.body.lastname};
              User.create(data).then(function(newUser, created) {
                  if (!newUser) {
                      return done(null, false);
                  }
                  if (newUser) {
                      return done(null, newUser);
                  }
              });
          }
        });
      }));
      passport.serializeUser(function(user, done) {
          done(null, user.id);
      });
      passport.deserializeUser(function(id, done) {
          User.findById(id).then(function(user) {
              if (user) {
                  done(null, user.get());
              } else {
                  done(user.errors, null);
              }
          });
      });

}
