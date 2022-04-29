const express = require('express');
const config = require('./configs');

const app = express();

app.use(express.json());

app.listen(config[process.env.NODE_ENV || 'development'].server.port);
