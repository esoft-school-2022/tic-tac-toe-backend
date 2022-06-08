const express = require('express');
const {catchErrors, log, collectMetrics} = require('./middlewares');
const api = require('./routes');

module.exports = ({config, db, auth, logger, metrics}) => {
  const app = express();

  app.use(express.json());
  app.use(collectMetrics(metrics, config.metrics.prefix));
  app.use(log(logger));
  app.use(auth.initialize);
  app.use(api({config, db, auth}));
  app.use(catchErrors);

  return app;
};
