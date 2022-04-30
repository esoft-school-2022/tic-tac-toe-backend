const express = require('express');
const config = require('./configs');
const routes = require('./src/routes');
const {catchErrors} = require('./src/middlewares');

const app = express();

app.use(express.json());
app.use('/api', routes);
app.use(catchErrors);

app.listen(config[process.env.NODE_ENV || 'development'].server.port);
