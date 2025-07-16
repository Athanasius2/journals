import * as fsPromises from 'node:fs/promises';

import express from 'express';
import session from 'express-session';
import { Issuer, generators } from 'openid-client';
import { cognitoSecret } from './client-secret.mjs';
import open from 'open';

// variable declarations ///////////////////////////////////////////////////////////////////////
const app = express();
let server;
const tokenFilePath = '../tokens.json';

let client;

// If we need to log in using the browser, pause execution until login finishes
var finished = false;

// check if the tokens are expired. if they are, try and get new ones
export async function checkTokens(){
  await initializeClient().catch(console.error);
  getTokens();
}

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

async function getTokens(){
  try{
    console.log("Reading tokens file...");
    var tokenString = await fsPromises.readFile(tokenFilePath); 
    var tokens = JSON.parse(tokenString);
    var current_time = Math.ceil(Date.now() / 1000)
    console.log(`Expires at:\t${tokens.expires_at}\nCurrent time:\t${current_time}`);
    if (tokens.expires_at < current_time){
      console.log("Access token expired: attempting refresh...");
      tokens = refreshTokens();
      if (tokens !== false) {
        console.log(tokens);
        console.log("Success!");
        console.log("Writing tokens to file...");
        await fsPromises.writeFile(tokenFilePath, JSON.stringify(tokens));
        console.log("Success!");
      }
      else {
        console.log("Token refresh failed: attempting to get new tokens...");
        newTokens();
      }
    }
    console.log("Tokens up to date");
  }
  catch(err){
    // file does not exist
    if (err.code === 'ENOENT'){
      console.log("Token file does not exist... ");
      // make user log in to create tokens
      newTokens();
    }
    // some other error
    else{
      console.log("Error getting tokens: ", err);
    }
  }
}

// tokens is an output parameter 
async function refreshTokens(){
  try {
    var tokens = await client.refresh(tokens.refresh_token);
    return tokens;
  }
  catch {
    return false;
  }
}

// open a browser to initialize login and then listen for a response
async function newTokens(){
  await initHandlers();
  server = app.listen(4269, () => console.log("Listening on port 4269...") );
  open("http://localhost:4269/init");
  // periodically check if we are done logging in to the application
  while (await sleepUntilDone());
}

// check if 'finished' has been set to true after 100 ms
function sleepUntilDone() {
  return new Promise ( (resolve) => {
    setTimeout( () => { resolve( finished === true )}, 100);
  });
}

// set up express path bindings
async function initHandlers(){
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
      console.log(tokenSet);
      console.log(userInfo);
      console.log("Writing token file...");
      await fsPromises.writeFile(tokenFilePath, JSON.stringify(tokenSet));
      console.log("Success!");
    } catch (err) {
      console.log(err);
    }
    res.redirect("https://gabekan.dev");
    // tell the server to stop listening and let the app know that we're done logging in.
    server.close();
    finished = true;
  });
}

