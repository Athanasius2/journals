import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);

export const handler = async (event, context, callback) => {
  const token = event.authorizationToken?.replace("Bearer ", "");
  // no token provided
  if (!token) return callback("Unauthorized");

  jwt.verify(token, getKey, function(err, decoded) {
    if(err) {
      console.log(err);
      callback(err.name);
    }
    else {
      console.log(decoded);
      // get username so we can look up user id in our own table
      const params = {
        TableName: "users",
        Key: {
          cognito_username: decoded.username
        }
      };

      try{
        docClient.send(new GetCommand(params)).then( (data) => {
          console.log(data)

          const pathId = event['pathParameters']['id'];
          console.log(pathId);

          callback(null, generatePolicy(decoded.username, 'Allow',  event.methodArn) );

        });
      }
      catch (err) {
        console.log(err);
      }
    }
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

var generatePolicy = function(principalId, effect, resource) {
  var authResponse = {};

  authResponse.principalId = principalId;
  if (effect && resource) {

    var policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];

    var statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;

    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  return authResponse;
};
