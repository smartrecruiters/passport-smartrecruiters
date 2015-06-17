# Passport-Smartrecruiters

[Passport](http://passportjs.org/) strategy for authenticating with [Smartrecruiters](https://www.smartrecruiters.com/)
using the OAuth 2.0 API.

This module lets you authenticate using Smartrecruiters in your Node.js applications.
By plugging into Passport, Smartrecruiters authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install

    $ npm install passport-smartrecruiters

## Usage

#### Configure Strategy

The Smartrecruiters authentication strategy authenticates users using a Smartrecruiters account
and OAuth 2.0 tokens.  The strategy requires a `verify` callback, which accepts
these credentials and calls `done` providing a user, as well as `options`
specifying a client ID, client secret, and callback URL.

    passport.use(new SmartrecruitersStrategy({
        clientID: SMARTRECRUITERS_CLIENT_ID,
        clientSecret: SMARTRECRUITERS_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/smartrecruiters/callback"
      },
      function(accessToken, refreshToken, profile, done) {
        User.findOrCreate({ smartrecruiters_id: profile.id }, function (err, user) {
          return done(err, user);
        });
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'smartrecruiters'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/smartrecruiters',
      passport.authenticate('smartrecruiters'));

    app.get('/auth/smartrecruiters/callback', 
      passport.authenticate('smartrecruiters', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });

## Examples

For a complete, working example, refer to the [login example](https://github.com/smartrecruiters/passport-smartrecruiters/tree/master/examples/login).

## Credits

  - [Kamil Sobol](http://github.com/sobolk)

## License

[The MIT License](http://opensource.org/licenses/MIT)



