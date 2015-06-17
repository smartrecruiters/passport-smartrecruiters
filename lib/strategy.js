/**
 * Module dependencies.
 */
var util = require('util')
    , OAuth2Strategy = require('passport-oauth2')
    , InternalOAuthError = require('passport-oauth2').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Smartrecruiters authentication strategy authenticates requests by delegating to
 * Smartrecruiters using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Smartrecruiters application's Client ID
 *   - `clientSecret`  your Smartrecruiters application's Client Secret
 *   - `callbackURL`   URL to which Smartrecruiters will redirect the user after granting authorization
 *   - `scope`         array of permission scopes to request.  valid scopes include:
 *                     'r_jobs' or none.
 *                     (see http://dev.smartrecruiters.com/ for more info)
 *
 * Examples:
 *
 *     passport.use(new SmartrecruitersStrategy({
 *         clientID: '123456789',
 *         clientSecret: 'shhh-its-a-secret',
 *         callbackURL: 'https://www.example.net/auth/smartrecruiters/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
    options = options || {};
    options.authorizationURL = options.authorizationURL || 'https://www.smartrecruiters.com/identity/oauth/allow';
    options.tokenURL = options.tokenURL || 'https://www.smartrecruiters.com/identity/oauth/token';
    options.scopeSeparator = options.scopeSeparator || ' ';
    options.customHeaders = options.customHeaders || {};

    if (!options.customHeaders['User-Agent']) {
        options.customHeaders['User-Agent'] = options.userAgent || 'passport-smartrecruiters';
    }

    OAuth2Strategy.call(this, options, verify);
    this.name = 'smartrecruiters';
    this._userProfileURL = options.userProfileURL || 'https://api.smartrecruiters.com/users/me';
    this._oauth2.useAuthorizationHeaderforGET(true);
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from Smartrecruiters.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `smartrecruiters`
 *   - `id`               the user's Smartrecruiters ID
 *   - `username`         the user's Smartrecruiters username
 *   - `displayName`      the user's full name
 *   - `emails`           the user's email addresses
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
    this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
        var json;

        if (err) {
            return done(new InternalOAuthError('Failed to fetch user profile', err));
        }

        try {
            json = JSON.parse(body);
        } catch (ex) {
            return done(new Error('Failed to parse user profile'));
        }

        var profile = {};
        profile.provider = 'smartrecruiters';
        profile._raw = body;
        profile._json = json;
        profile.id = json.id;
        profile.displayName = (json.firstName || "") + " " + (json.lastName || "");
        profile.username = json.email;
        profile.profileUrl = json.html_url;
        if (json.email) {
            profile.emails = [
                { value: json.email }
            ];
        }

        done(null, profile);
    });
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
