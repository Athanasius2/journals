import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, QueryCommand } from '@aws-sdk/lib-dynamodb';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);

export const handler = async (event) => {
  const token = event.authorizationToken?.replace("Bearer ", "");
  // no token provided
  if (!token) 
  {
    console.log("No token found");
    return {
      statusCode: 403, 
      body: JSON.stringify({message: "No token found"})
    };
  }
  console.log("token found");

  var decoded;
  try {
    decoded = await verifyToken(token, getKey)
    console.log("token verified");
  } 
  catch (err) {
    console.log(err);
    return {
        statusCode: 500,
        body: JSON.stringify({message : err.name})
    };
  }
  // get username so we can look up user id in our own table
  const params = {
    TableName: "users",
    KeyConditionExpression: "cognito_username = :pk",
    ExpressionAttributeValues: {
      ":pk": decoded.username
    },
    ProjectionExpression: "id"
  };

  try{
    var data = await docClient.send(new QueryCommand(params));
    //.then( (data) => {
    console.log(data)

    const pathId = event['pathParameters']['id'];
    const ddbId = data.Items[0].id ?? -1;
    console.log("Path id = ", pathId);
    console.log("DDB id = ", ddbId);
    console.log(pathId);
    if (pathId == ddbId){
      return {
        statusCode: 200,
        body: JSON.stringify( generatePolicy(decoded.username, 'Allow', event.methodArn) )
      }
    }
    return {
      statusCode: 403,
      body: JSON.stringify( generatePolicy(decoded.username, 'Deny', event.methodArn) )
    }
  }
  catch (err) {
    return { statusCode: 500, body: JSON.stringify( { message: "Failed to get user id from database"}) };
  }
};

// handle asyncronous token stuff
function verifyToken(token, key) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, key, (err, decoded) => {
      if (err){
        return reject(err);
      }
      resolve(decoded);
    });
  });
}

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
