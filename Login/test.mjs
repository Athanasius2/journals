import { initializeClient, client } from './app.mjs';

initializeClient().catch(console.error);

console.log(client)

