import express from 'express';
import session from 'express-session';
import { Issuer, generators } from 'openid-client';
import { sessionSecret, cognitoSecret } from './client-secret.mjs';
import open from 'open';

const app = express();

let client;
// Initialize OpenID Client
async function initializeClient() {
    const issuer = await Issuer.discover('https://cognito-idp.us-west-2.amazonaws.com/us-west-2_uKM5vTgkH');
    console.log('Discovered issuer', issuer.metadata);
    console.log("Starting client...");
    client = new issuer.Client({
        client_id: '2v04o0d5pva80o5et83vh9sfu4',
        client_secret: cognitoSecret,
        redirect_uris: ['https://localhost:4269/'],
        response_types: ['code']
    });
    console.log('Client created: ', client.metadata);
};
await initializeClient().catch(console.error);

const nonce = generators.nonce();
const state = generators.state();

const authUrl = client.authorizationUrl({
  scope: 'email openid phone',
  state: state,
  nonce: nonce,
});

open(authUrl);

app.listen(4269, () => console.log("Listening on port 4269..."))
app.get('/', (req, res) => {
  if (!req.session.userInfo){
    console.log('Authentication failed!!');
    return;
  }
  console.log('Session info: ', req.session.userInfo);
});
