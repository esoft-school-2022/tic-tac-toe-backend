const express = require('express');
const cookieParser = require('cookie-parser');
const {catchErrors, logRequests, collectMetrics} = require('./middlewares');
const api = require('./routes');

module.exports = ({config, db, auth, logger, metrics, broker}) => {
  const app = express();

  app.use(express.json());
  app.use(cookieParser(config.auth.secret));
  app.use(collectMetrics(metrics, config.metrics.prefix));
  app.use(logRequests(logger));
  app.use(auth.initialize);
  app.use(api({config, db, auth, broker}));
  app.use(catchErrors);

  return app;
};
