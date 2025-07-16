import { readFile } from 'node:fs';
import { handler } from './index.mjs';
import { checkTokens } from '../Login/app.mjs';

await checkTokens();
readFile("../tokens.json", null, async (err, data) => {
  if (err) {
    console.log(err);
  }
  else {
    var tokens = JSON.parse(data);
    var event = {
      "type": "TOKEN",
      "authorizationToken": tokens.access_token,
      "methodArn": "arn:aws:execute-api:us-east-1:123456789012:example/prod/POST/{proxy+}",
      "pathParameters": {
        "id": 0
      },
    };

    var ret = await handler(event);
    console.log("test returned: ", ret);
  }
});




