const http = require('http');
const configs = require('./configs');
const configureApp = require('./src/app');
const configureDb = require('./src/db');
const configureSockets = require('./src/sockets');

(async() => {
  const injects = {};

  injects.config = configs[process.env.NODE_ENV || 'development']
  injects.db = await configureDb(injects);
  injects.server = http.createServer(await configureApp(injects));

  injects.server.listen(process.env.PORT || 8080, await configureSockets(injects));
})();
