import express from 'express';
import  session from 'express-session';
import { Issuer, generators } from 'openid-client';
import { sessionSecret, cognitoSecret } from './client-secret.mjs';

const app = express();

let client;
// Initialize OpenID Client
async function initializeClient() {
    const issuer = await Issuer.discover('https://cognito-idp.us-west-2.amazonaws.com/us-west-2_uKM5vTgkH');
    client = new issuer.Client({
        client_id: '2v04o0d5pva80o5et83vh9sfu4',
        client_secret: cognitoSecret,
        redirect_uris: ['https://gabekan.dev/'],
        response_types: ['code']
    });
};
initializeClient().catch(console.error);

app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false
}));

const checkAuth = (req, res, next) => {
  if (!req.session.userInfo) {
    req.isAuthenticated = false;
  }
  else {
    req.isAuthenticated = true;
  }
  next();
};

app.get('/', checkAuth, (req, res) => {
  res.render('home', {
    isAuthenticated: req.isAuthenticated,
    userInfor: req.session.userInfo
  });
});

app.get('/login', (req, res) => {
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

// Helper function to get the path from the URL. Example: "http://localhost/hello" returns "/hello"
function getPathFromURL(urlString) {
    try {
        const url = new URL(urlString);
        return url.pathname;
    } catch (error) {
        console.error('Invalid URL:', error);
        return null;
    }
}

app.get(getPathFromURL('https://gabekan.dev/'), async (req, res) => {
    try {
        const params = client.callbackParams(req);
        const tokenSet = await client.callback(
            'https://gabekan.dev/',
            params,
            {
                nonce: req.session.nonce,
                state: req.session.state
            }
        );

        const userInfo = await client.userinfo(tokenSet.access_token);
        req.session.userInfo = userInfo;

        res.redirect('/');
    } catch (err) {
        console.error('Callback error:', err);
        res.redirect('/');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    const logoutUrl = `https://us-west-2ukm5vtgkh.auth.us-west-2.amazoncognito.com/logout?client_id=2v04o0d5pva80o5et83vh9sfu4`;
    res.redirect(logoutUrl);
});
