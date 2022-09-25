var express = require('express');
var csrf = require('csurf');
var LocalStrategy = require('passport-local');
var crypto = require('crypto');

exports = module.exports = function(authenticator, usersDB) {
  var router = express.Router();
  
  /* Configure password authentication strategy.
   *
   * The `LocalStrategy` authenticates users by verifying a username and password.
   * The strategy parses the username and password from the request and calls the
   * `verify` function.
   *
   * The `verify` function queries the database for the user record and verifies
   * the password by hashing the password supplied by the user and comparing it to
   * the hashed password stored in the database.  If the comparison succeeds, the
   * user is authenticated; otherwise, not.
   */
  authenticator.use(new LocalStrategy(function verify(username, password, cb) {
    usersDB.get('SELECT * FROM users WHERE username = ?', [ username ], function(err, row) {
      if (err) { return cb(err); }
      if (!row) { return cb(null, false, { message: 'Incorrect username or password.' }); }
    
      crypto.pbkdf2(password, row.salt, 310000, 32, 'sha256', function(err, hashedPassword) {
        if (err) { return cb(err); }
        if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) {
          return cb(null, false, { message: 'Incorrect username or password.' });
        }
        return cb(null, row);
      });
    });
  }));
  
  
  var messages = function(req, res, next) {
    var msgs = req.session.messages || [];
    res.locals.messages = msgs;
    res.locals.hasMessages = !! msgs.length;
    req.session.messages = [];
    next();
  }
  
  /* GET /login
   *
   * This route prompts the user to log in.
   *
   * The 'login' view renders an HTML form, into which the user enters their
   * username and password.  When the user submits the form, a request will be
   * sent to the `POST /login/password` route.
   */
  router.get('/login',
    csrf(),
    messages,
    function(req, res, next) {
      res.render('login', { csrfToken: req.csrfToken() });
    });
  
  /* POST /login/password
   *
   * This route authenticates the user by verifying a username and password.
   *
   * A username and password are submitted to this route via an HTML form, which
   * was rendered by the `GET /login` route.  The username and password is
   * authenticated using the `local` strategy.  The strategy will parse the
   * username and password from the request and call the `verify` function.
   *
   * Upon successful authentication, a login session will be established.  As the
   * user interacts with the app, by clicking links and submitting forms, the
   * subsequent requests will be authenticated by verifying the session.
   *
   * When authentication fails, the user will be re-prompted to login and shown
   * a message informing them of what went wrong.
   */
  router.post('/login/password',
    csrf(),
    authenticator.authenticate('local', {
      successReturnToOrRedirect: '/',
      failureRedirect: '/login',
      failureMessage: true
    }));
    
  /* POST /logout
   *
   * This route logs the user out.
   */
  router.post('/logout',
    csrf(),
    function(req, res, next) {
      req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
    });
    
  /* GET /signup
   *
   * This route prompts the user to sign up.
   *
   * The 'signup' view renders an HTML form, into which the user enters their
   * desired username and password.  When the user submits the form, a request
   * will be sent to the `POST /signup` route.
   */
  router.get('/signup',
    csrf(),
    messages,
    function(req, res, next) {
      res.render('signup', { csrfToken: req.csrfToken() });
    });
    
  /* POST /signup
   *
   * This route creates a new user account.
   *
   * A desired username and password are submitted to this route via an HTML form,
   * which was rendered by the `GET /signup` route.  The password is hashed and
   * then a new user record is inserted into the database.  If the record is
   * successfully created, the user is logged in.
   */
  router.post('/signup', csrf(), function(req, res, next) {
    var salt = crypto.randomBytes(16);
    crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', function(err, hashedPassword) {
      if (err) { return next(err); }
      
      db.run('INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', [
        req.body.username,
        hashedPassword,
        salt
      ], function(err) {
        if (err) { return next(err); }
        
        var user = {
          id: this.lastID,
          username: req.body.username
        };
        req.login(user, function(err) {
          if (err) { return next(err); }
          res.redirect('/');
        });
      });
    });
  });
  
  return router;
};
