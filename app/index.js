var path = require('path');
var express = require('express');
var bodyParser = require('body-parser');
var crypto = require('crypto');

var app = express();

// The API uses a single secret key (only internal) to encrypt the token signatures
//   This key should be unique for each instance. Preferably randomly generated on installation
var secretKey = 'directus_da_best';

// This would be directus_users in the database
var users = [
  {
    id: 1,
    username: 'rijk',
    password: 'password',
    fullName: 'Rijk van Zanten',
    permissionGroup: 'administrator'
  },
  {
    id: 2,
    username: 'welling',
    password: 'password',
    fullName: 'Welling Guzmán',
    permissionGroup: 'administrator'
  }
];

/**
 * Base64 encodes given value
 * @param  {String} value Value to encode
 * @return {String}       Encoded value
 */
function base64encode(value) {
  return Buffer.from(value).toString('base64');
}

/**
 * Base64 decodes given value
 * @param  {String} value Value to decode
 * @return {String}       Decoded value
 */
function base64decode(value) {
  return Buffer.from(value, 'base64').toString('ascii');
}

app
  // Extract JSON from POST request body
  .use(bodyParser.json())

  // posting /login creates a token if valid auth and redirects to the homepage
  .post('/login', function (req, res) {
    var credentials = req.body;

    // Get user object out of users "database" by matching username
    var matchedUser = users.filter(function (user) {
      return user.username === credentials.username;
    })[0];

    // IRL you'd hash the password and match it to the hashed saved password
    if (matchedUser.password === credentials.password) {
      // The dreaded header part. We won't be using it right away, but include it to be spec compliant
      //   and give us the ability to start supporting multiple algorithms at a later point in time
      var header = { typ: 'JWT', alg: 'HS1' };
      header = JSON.stringify(header); // Convert JS object to JSON

      // Create a Unix timestamp 2 hours in the future to include in the payload
      var payloadExpiryDate = new Date();
      payloadExpiryDate.setHours(payloadExpiryDate.getHours() + 2);

      // We include any data we need to identify the user or his/her permissions
      //   This payload is only base64 encoded so can be viewed publicly
      //
      // This payload will not be changed client side, unless the user tries to hack
      //   his way into another usergroup. If the user alters the payload client side,
      //   the signature part of the token will not match, but we'll get to that in a bit
      var payload = {
        id: matchedUser.id,
        permissionGroup: matchedUser.permissionGroup,
        exp: payloadExpiryDate // Expiry date in Unix timestamp, see above variable
      };
      payload = JSON.stringify(payload); // Convert JS object to JSON

      // Join the first two parts of the token with a dot '.'
      var unsignedToken = base64encode(header) + '.' + base64encode(payload);

      // Encrypt the header and payload joined by '.' to create the signature (3rd) part of the token:
      //   implementation of actual encryption will differ
      var signature = crypto.createHmac('sha256', secretKey).update(unsignedToken).digest('hex');

      // Join the non-encrypted header and payload with the encrypted signature to create the actual token:
      var accessToken = base64encode(header) + '.' + base64encode(payload) + '.' + base64encode(signature);

      // Send the access token to the user:
      res.json({
        access_token: accessToken
      });
    } else {
      // if not logged in
      res.status(403).json({
        error: 'Wrong credentials'
      });
    }
  })

  // Getting / checks if the user is logged in (by matching the token) and redirects home if valid
  .get('/', function (req, res) {
    // Get token from Authorization header
    var accessToken = req.headers.authorization || false;

    if (accessToken) {
      accessToken = accessToken.replace('Bearer: ', ''); // Remove Bearer flag from auth header

      // We know the access token contains of three parts joined by a dot '.'
      // base64encode(header) + '.' + base64encode(payload) + '.' + base64encode(signature)
      //
      // We want to extract these three parts back to their original values to be able to
      //   check the validity
      var tokenParts = accessToken.split('.');

      var header = tokenParts[0];
      header = base64decode(header);
      header = JSON.parse(header);

      var payload = tokenParts[1];
      payload = base64decode(payload);
      payload = JSON.parse(payload);

      var signature = tokenParts[2];
      signature = base64decode(signature);

      // With the three parts extracted, we first check if the header and payload
      //   are valid by checking the signature
      //
      // We do this by creating a new signature and comparing it to the one in the access token
      var unsignedToken = tokenParts[0] + '.' + tokenParts[1];
      var referenceSignature = crypto.createHmac('sha256', secretKey).update(unsignedToken).digest('hex');

      // If the newly generated reference signature is the same as the one in the access token, we know
      //   that the header and payload haven't been tempered with (as that would change the signature)
      //
      // Since we encrypt the signature with a secret key specific to this instance,
      //   we also know it came from a valid login attempt, since the user couldn't
      //   have generated this access token without that secret secretKey
      if (referenceSignature === signature) {
        // Now we know we are dealing with a valid user, we can check the `exp` field of the
        //   payload to see if it has expired:
        var expiryDate = payload.exp;

        if (expiryDate < Date.now()) {
          res.status(403).json({
            error: 'Token has expired'
          });
        } else {
          // Token is valid and hasn't expired. We can now use the info in the payload to get
          //   the user specific private data and render the result
          var allUserDataOfLoggedInUser = users.filter(function (user) {
            return user.id === payload.id;
          })[0];

          res.json(allUserDataOfLoggedInUser);
        }
      } else {
        res.status(403).json({
          error: 'Invalid signature. Access token header/payload has changed'
        });
      }
    } else {
      res.status(400).json({
        error: 'No authorization header passed'
      });
    }
  })

  // Start the server on port 3000
  .listen(3000, function () {
    console.log('Server running at http://localhost:3000');
  });
