var express = require('express');
var router = express.Router();
var passport = require('passport');
var dotenv = require('dotenv');
var util = require('util');
var url = require('url');
var querystring = require('querystring');
var dns = require('dns');
var request = require('request');
var jwt = require('jsonwebtoken');

dotenv.config();

var auth0_management_api_token;

// ========== Routes =============

/**
 * GET /prelogin
 *
 * Performs the pre-login checks when the user entered his user id in the frontend
 * and hit the "Login with ID4me" button.
 *
 * The prelogin phase contains multiple steps:
 *  - fetch Auth0 management API token
 * - check for DNS TXT entry at user's domain
 * - check if custom connection at Auth0 exists for user's IdP
 * - optionally: register Auth0 client at user's IdP and create custom connection for this IdP at Auth0
 *
 * When the prelogin phase is finished, it continues with the actual login phase.
 */
router.get('/prelogin', (req, res) => {
  handlePreLogin(req, res);
});


/**
 * GET /login
 *
 * Handles the actual login, which is the triggering of the /authorization request towards Auth0.
 * When the authentication flow is finished, the callback will be called.
 */
router.get('/login', (req, res, next) => {
  var login_options = {
    scope: process.env.SCOPE,
    connection: req.query.connection,
    login_hint: req.query.login_hint
  };
  passport.authenticate('auth0', login_options)(req, res, next)
});


//
/**
 * GET /callback
 *
 * The callback when the authentication flow finished at Auth0 side. Upon successful authentication,
 * the callback will redirect to the user profile page and display the user profile info (ID token claims)
 */
router.get('/callback', function (req, res, next) {
  passport.authenticate('auth0', function (err, user, info) {
    if (err) { return next(err); }
    if (!user) { return res.redirect('/login'); }
    req.logIn(user, function (err) {
      if (err) { return next(err); }
      const returnTo = req.session.returnTo;
      delete req.session.returnTo;
      res.redirect(returnTo || '/user');
    });
  })(req, res, next);
});

/**
 * GET /logout
 *
 * Performs session logout and redirect to homepage.
 */
router.get('/logout', (req, res) => {

  req.logout();

  var returnTo = req.protocol + '://' + req.hostname;
  var port = req.connection.localPort;
  if (port !== undefined && port !== 80 && port !== 443) {
    returnTo += ':' + port;
  }
  var logoutURL = new url.URL(
    util.format('https://%s/logout', process.env.AUTH0_DOMAIN)
  );
  var searchString = querystring.stringify({
    client_id: process.env.AUTH0_CLIENT_ID,
    returnTo: returnTo
  });
  logoutURL.search = searchString;

  res.redirect(logoutURL);
});


// ========== Helper Functions =============

/**
 * Starting point for the prelogin checks (triggered from GET /prelogin route).
 * First, fetches an access token for the Auth0 Managemenet API.
 */
function handlePreLogin(req, res) {
  getManagementApiToken(req, res);
}

/**
 * Gets an Auth0 Management API Token. Currently doesn't store it anywhere.
 * Upon access token retrieval, it calls the checkDns function.
 */
function getManagementApiToken(req, res) {
  var accessTokenExistsAndNotExpired = false;

  // check if we already have a valid non-expired access token in memory.
  if (auth0_management_api_token) {
    var decoded = jwt.decode(auth0_management_api_token, {complete: true});
    if (new Date().getTime() > decoded.payload.exp) {
      accessTokenExistsAndNotExpired = true;
      checkDns(req, res);
    }
  }

  // otherwise, request new access token for Auth0 management API
  if (!accessTokenExistsAndNotExpired) {
    var options = { method: 'POST',
      url: 'https://' + process.env.AUTH0_DOMAIN + '/oauth/token',
      headers: { 'content-type': 'application/json' },
      body: '{"client_id":"' + process.env.AUTH0_CLIENT_ID + '","client_secret":"' + process.env.AUTH0_CLIENT_SECRET + '","audience":"https://' + process.env.AUTH0_DOMAIN + '/api/v2/","grant_type":"client_credentials"}' };

    request(options, function (error, response, body) {

      if (error || response.statusCode === 400 || response.statusCode === 401) {
        res.redirect('/');
      } else {
        auth0_management_api_token = JSON.parse(response.body)['access_token'];
        checkDns(req, res);
      }
    });
  }
}


/**
 * Check the DNS of the user's domain for a txt entry under _openid.<user_id>
 * This text entry call look something like this: v=OID1;iss=id.test.denic.de;clp=identityagent.de
 * and contains the user's identity authority as well as identity agent.
 *
 * It then checks the Auth0 management API to see if a custom social connection for this
 * particular identity authority already exists or not.
 *
 * If not yet existing, it calls the dynamicClientRegistrationAtAuthority
 * method to dynamcally register a client at the identity authority as well as
 * creating a custom social connection for it at Auth0.
 *
 * If existing, it redirects to the actual /login.
 */
function checkDns(req, res) {
  String.prototype.replaceAll = function(search, replacement) {
      var target = this;
      return target.replace(new RegExp(search, 'g'), replacement);
  };

  dns.resolveTxt('_openid.' + req.query.userid, function (err, addresses) {
    if (err) throw err;
    addresses.forEach(function (a) {
      a.forEach(function (b) {
        var idAuthority = b.split(";")[1].split("=")[1]; // idAuthority = iss
        var connectionName = idAuthority.replaceAll("\\.", "-");

        request('https://' + process.env.AUTH0_DOMAIN + '/api/v2/connections?name=' + connectionName,
        {
          headers: {
            'Authorization': 'Bearer ' + auth0_management_api_token
          },
        }, function (error, response, body) {
          // if connection doesn't exist, create
          if (response.statusCode == 400 || JSON.parse(body).length===0) {
            dynamicClientRegistrationAtAuthority(req, res, idAuthority);
          } else if (response.statusCode === 200 && JSON.parse(body).length === 1) { // connection already exists
            res.redirect('/login?connection=' + connectionName + '&login_hint=' + req.query.userid);
          }
        });

      });
    });
  });
};


/**
 * Dynamically registers a client at the identity authority by first fetching the
 * OIDC Discovery document and then uses the registration endpoints to register a client.
 * Afterwards, the dynamicConnectionRegistrationAtAuth0 function is called to create
 * a custom social connection at Auth0 for this identity authority.
 */
function dynamicClientRegistrationAtAuthority(req, res, idAuthority) {
  var connectionName = idAuthority.replaceAll("\\.", "-");

  // OIDC Discovery
  request('https://' + idAuthority + '/.well-known/openid-configuration', function (error, response, body) {

    if (response.statusCode == 200) {

      var idAuthorityDiscoveryDoc = JSON.parse(body);

      var newClient = {
        "client_name":"Auth0 ID4me Demo",
        "application_type":"web",
        "redirect_uris":["https://" + process.env.AUTH0_DOMAIN + "/login/callback", "https://www.yourcompany.com"],
        "logo_uri":"https://www.yourcompany.com/id4me/logo.png",
        "policy_uri":"https://www.yourcompany.com/id4me/privacy",
        "tos_uri":"https://www.yourcompany.com/id4me/tos",
        "token_endpoint_auth_method" : "client_secret_basic"
      };

      request({
        url: idAuthorityDiscoveryDoc['registration_endpoint'],
        method: 'POST',
        json: newClient
      }, function (error, response, body) {
        if (response.statusCode == 200 || response.statusCode == 201) {
          var idAuthorityClient = body;
          dynamicConnectionRegistrationAtAuth0(req, res, idAuthorityDiscoveryDoc, idAuthorityClient);
        } else {
          res.redirect('/');
        }
      });

    } else {
      res.redirect('/');
    }

  });

};


/**
 * Registers a custom social connection for the user's identity authority at Auth0 side.
 * It then redirects further to the actual /login.
 */
function dynamicConnectionRegistrationAtAuth0(req, res, idAuthorityDiscoveryDoc, idAuthorityClient) {
  var connectionName = idAuthorityDiscoveryDoc['issuer'].replace('https://', '').replaceAll("\\.", "-");
  var newConn =
    {
      "options": {

        "scripts": {
          "fetchUserProfile": "async function(accessToken, ctx, cb) {\n  const jwt = require('jsonwebtoken');\n  const axios = require(\"axios\");\n  var idTokenPayload;\n  var profile = {};\n  try {\n    const r = await axios.get('" + idAuthorityDiscoveryDoc['userinfo_endpoint'] + "', {\n      headers: {\n        'Authorization': 'Bearer ' + accessToken\n      }\n    });\n    var b = r.data;\n    var claim_sources = b._claim_sources;\n    var claim_names = b._claim_names;\n    var access_token, endpoint, scope, profile, userinfo;\n\n    // loop through all claim sources (often probably just one)\n    for (var cs in claim_sources) {\n      if (claim_sources.hasOwnProperty(cs)) {\n        access_token = claim_sources[cs].access_token;\n        endpoint = claim_sources[cs].endpoint;\n        scope = '';\n        for (var cn in claim_names) {\n          if (claim_names.hasOwnProperty(cn)) {\n            if (claim_names[cn] === cs) {\n              scope += ' ' + cn;\n            }\n          }\n        } // for claim_names\n\n        const response = await axios.get(endpoint, {\n          headers: {\n            'Authorization': 'Bearer ' + access_token\n          }\n        });\n        idTokenPayload = jwt.decode(response.data);\n\n        // loop through all claim names\n        for (cn in claim_names) {\n          if (claim_names.hasOwnProperty(cn)) {\n            if (claim_names[cn] === cs) {\n              profile[cn] = idTokenPayload[cn];\n            }\n          }\n        } // for claim_names\n\n        profile.user_id = idTokenPayload.sub;\n        profile.preferred_username = idTokenPayload['id4me.identifier'];\n\n      }\n\n    } // for claim_sources\n\n    // ====\n    cb(null, profile);\n\n  } catch (e) {\n    console.log('Error getData: ' + e);\n    cb(null, profile);\n  }\n\n}"
        },
        "client_id": idAuthorityClient['client_id'],
        "client_secret": idAuthorityClient['client_secret'],
        "authorizationURL": idAuthorityDiscoveryDoc['authorization_endpoint'],
        "tokenURL": idAuthorityDiscoveryDoc['token_endpoint'],
        "scope": process.env.SCOPE,
        "customHeaders": {
          "Authorization": "Basic " + new Buffer(idAuthorityClient['client_id'] + ':' + idAuthorityClient['client_secret']).toString('base64')
        },
        "upstream_params": {
          "login_hint": {
            "alias": "login_hint"
          }
        },
        "metadata": {
          "registration_access_token": idAuthorityClient['registration_access_token'],
          "registration_client_uri": idAuthorityClient['registration_client_uri']
        }
      },
      "strategy": "oauth2",
      "name": connectionName,
      "is_domain_connection": false,
      "enabled_clients": [process.env.AUTH0_CLIENT_ID]
    };

  request({
    url: 'https://' + process.env.AUTH0_DOMAIN + '/api/v2/connections',
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + auth0_management_api_token
    },
    json: newConn
  }, function (error, response, body) {
    if (response.statusCode == 201) {
      res.redirect('/login?connection=' + connectionName + '&login_hint=' + req.query.userid);
    } else {
      res.redirect('/');
    }
  });
}

module.exports = router;
