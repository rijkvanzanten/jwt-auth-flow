# jwt-auth-flow
Reference API to demonstrate JWT functionality.

Implements the JWT spec as lightly as possible to show the way it works.

## Installation
This demo uses two dependencies: `express` to get a simple API up and running and `body-parser` to extract the JSON values of post requests.
To install these dependencies, run `npm install`.

This app requires Node > 6, because of the API change in the Buffer object.

## Usage
To start the app, run `npm start`.

The app has two "users" hardcoded in it's "database".
To retrieve a valid JWT access token, send a POST request to `/login` with a username and password in the body as JSON:
```json
{
  "username": "rijk",
  "password": "password"
}
```

This JWT contains the user's ID and permissions group in the payload, which the server uses to extract the full user object from the database if a valid token has been passed.
To view this full user object, send a GET request to `/` with the JWT in the Authorization header:
```
Authorization: Bearer: <jwt>
```

The server knows these things from the given token:
- What algorithm was used to create the signature
- That it's a JWT
- Any info we put in the payload (in this case user ID, user permissions group and expiry date)
- It's validity by recreating a signature from the given header and payload and matching it to the given signature

Since the header and payload part are only base64 encoded, and not hashed, the user can extract the data from the header and payload. However, when the user tries to alter the data in any of these two (for example, increase permissions level), the signature would be out of sync.
When the user tries to use an altered token, the recreated signature would be different from the passed signature, making the token invalid.
