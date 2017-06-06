var authController = require('../controllers/authController.js');

module.exports = function(app, passport) {

    app.get('/signin', authController.signin);

    app.get('/signup', authController.signup);

    app.post('/signup', passport.authenticate('local-signup', {
            successRedirect: '/dashboard',
            failureRedirect: '/signup'
        }
    ));

    app.get('/dashboard', isLoggedIn, authController.dashboard);

    app.get('/logout', authController.logout);

    app.post('/signin', passport.authenticate('local-signin', {
            successRedirect: '/dashboard',
            failureRedirect: '/signin'
        }));

    app.get('/api/auth/linkedin/callback',
      passport.authenticate('oauth2', { failureRedirect: '/login' }),
      function(req, res) {
        console.log("REQUEST", req)
        // Successful authentication, redirect home.
        res.redirect('/dashboard');
    });

}

function isLoggedIn(req, res, next) {

    if (req.isAuthenticated())

        return next();

    res.redirect('/signin');

}
