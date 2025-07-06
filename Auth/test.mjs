import {handler} from './index.mjs';
import express from 'express';

const app = express();
const port = 4270;

app.get('/', (req, res) => {
  const authHeader = req.headers['authorization'];
  const event = {authenticateToken: authHeader};

  handler(event);
  return res.status(200)
});

app.listen(port);

