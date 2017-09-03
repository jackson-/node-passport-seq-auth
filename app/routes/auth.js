const authController = require('../controllers/authController.js');
const passport = require('passport');


module.exports = require('express').Router()

    .get('/signin', authController.signin)

    .get('/signup', authController.signup)

    .post('/signup', passport.authenticate('local-signup', {
            successRedirect: '/dashboard',
            failureRedirect: '/signup'
        }
    ))

    .get('/dashboard', isLoggedIn, authController.dashboard)

    .get('/logout', authController.logout)

    .post('/signin', passport.authenticate('local-signin', {
            successRedirect: '/dashboard',
            failureRedirect: '/signin'
        }))

function isLoggedIn(req, res, next) {

    if (req.isAuthenticated())

        return next();

    res.redirect('/signin');

}
