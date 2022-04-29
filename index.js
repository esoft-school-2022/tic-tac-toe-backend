const express = require('express');
const config = require('./configs');
const routes = require('./src/routes');

const app = express();

app.use(express.json());

app.use('/api', routes);

app.listen(config[process.env.NODE_ENV || 'development'].server.port);
