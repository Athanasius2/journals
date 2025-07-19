import { readFile } from 'node:fs/promises';
import { exec } from 'child_process';

var tokenString = await readFile("../tokens.json");
var tokens = JSON.parse(tokenString);

const callback = (err, stdout, stderr) => {
  if (err) {
    console.log(err);
  }
  console.log("stdout: ", stdout);
}

exec(`curl -H 'Authorization: Bearer ${tokens.access_token}' https://3uw5fq2yfa.execute-api.us-east-2.amazonaws.com/testing/users/0`, callback);







