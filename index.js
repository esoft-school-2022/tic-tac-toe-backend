const http = require('http');
const configs = require('./configs');
const configureApp = require('./src/app');
const configureDb = require('./src/db');
const configureSockets = require('./src/sockets');

const config = configs[process.env.NODE_ENV || 'development'];
const db = configureDb({config});
const server = http.createServer(configureApp({config, db}));

server.listen(process.env.PORT || 8080, configureSockets({config, db, server}));
