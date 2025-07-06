import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

export const handler = async (event) => {
  const token = event.authenticateToken?.replace("Bearer ", "");
  // no token provided
  if (!token) return res.sendStatus(401);

  jwt.verify(token, getKey, function(err, decoded) {
    if(err) {
      console.log(err);
    }
    console.log(decoded);
  });

};

// Callback to get public key for token verification
function getKey(header, callback){
  // create a jwksClient for retrieving the signing key to verify the signature
  var client = jwksClient({jwksUri: process.env.PUBLIC_KEY_URL});

  client.getSigningKey(header.kid, function(err, key) {
    var signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}
