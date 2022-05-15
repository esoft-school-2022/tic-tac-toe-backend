const http = require('http');
const configs = require('./configs');
const configureApp = require('./src/app');
const configureBroker = require('./src/broker');
const configureDb = require('./src/db');
const configureSockets = require('./src/sockets');

(async() => {
  const injects = {};

  injects.config = configs[process.env.NODE_ENV || 'development']
  injects.db = await configureDb(injects);
  injects.broker = await configureBroker(injects);
  injects.server = http.createServer(await configureApp(injects));

  process.on(
    'SIGINT',
    async() => {
      try {
        await injects.db.destroy();
        await injects.broker.pub.disconnect();
        await injects.broker.sub.disconnect();

        process.exit(0);
      } catch (err) {
        process.exit(1);
      }
    }
  );

  injects.server.listen(process.env.PORT || 8080, await configureSockets(injects));
})();
