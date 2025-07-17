import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, QueryCommand } from '@aws-sdk/lib-dynamodb';


export const handler = async (event) => {
  const token = event.authorizationToken?.replace("Bearer ", "");
  const arnUser = event.methodArn.split('/')[4];
  // no token provided
  if (!token) 
  {
    console.log("No token found");
    return {message: "No token found"};
  }
  console.log("token found");

  var decoded;
  try {
    decoded = await verifyToken(token, getKey)
    console.log("token verified");
  } 
  catch (err) {
    console.log(err);
    return {message : err.name};
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

  const client = new DynamoDBClient({});
  const docClient = DynamoDBDocumentClient.from(client);

  var data;
  try{
    data = await docClient.send(new QueryCommand(params));
  }
  catch (err) {
    return {message : "Failed to retrieve user id from database" };
  }
  console.log(data);

  const userId = data.Items[0].id;
  console.log("User Id = ", userId);
  console.log("ARN user Id = ", arnUser);
  // check that the user id int he database matches the one in the arn from the event
  if (arnUser == userId){
    return  {
      principalId: userId,
      policyDocument: {
        Version: "2012-10-17",
        "Statement": [
          {
            Action: "execute-api:Invoke",
            Effect: "Allow",
            Resource: event.methodArn
          }
        ]
      },
      context: {
        userId: userId
      }
    };
  }
  else {
    return  {
      principalId: userId,
      policyDocument: {
        Version: "2012-10-17",
        "Statement": [
          {
            Action: "execute-api:Invoke",
            Effect: "Deny",
            Resource: event.methodArn
          }
        ]
      },
      context: {
        userId: userId
      }
    };
  }
}

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


