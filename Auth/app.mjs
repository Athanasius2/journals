import express from 'express';
import session from 'express-session';
import { Issuer, generators } from 'openid-client';
import { cognitoSecret } from './client-secret.mjs';
import open from 'open';

const app = express();

let client;
// Initialize OpenID Client
async function initializeClient() {
    const issuer = await Issuer.discover('https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Nnp9KqMgm');
    console.log('Discovered issuer', issuer.metadata);
    console.log("Starting client...");
    client = new issuer.Client({
        client_id: '7ak2kiulhsa4c9vt13uq32vcqh',
        client_secret: cognitoSecret,
        redirect_uris: ['http://localhost:4269/login'],
        response_types: ['code']
    });
    console.log('Client created: ', client.metadata);
};
await initializeClient().catch(console.error);

app.use(session({
    secret: "some secret",
    resave: false,
    saveUninitialized: false,
}));


app.get('/init', (req, res) => {
    const nonce = generators.nonce();
    const state = generators.state();

    req.session.nonce = nonce;
    req.session.state = state;


    const authUrl = client.authorizationUrl({
      scope: 'email openid phone',
      state: state,
      nonce: nonce,
    });

    res.redirect(authUrl);
    
});

app.get('/login', async (req, res) => {
    try{
        const params = client.callbackParams(req);
        const tokenSet = await client.callback(
            'http://localhost:4269/login',
            params,
            {
                nonce: req.session.nonce,
                state: req.session.state
            }
        );
        const userInfo = await client.userinfo(tokenSet.access_token);
        req.session.userInfo = userInfo;

        console.log(userInfo);
    } catch (err) {
        console.log(err);
    }
    res.redirect("https://gabekan.dev");
});

app.listen(4269, () => console.log("Listening on port 4269...") );
open("http://localhost:4269/init");


