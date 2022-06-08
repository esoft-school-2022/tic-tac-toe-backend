const express = require('express');
const {catchErrors, log} = require('./middlewares');
const api = require('./routes');

module.exports = ({config, db, auth, logger}) => {
  const app = express();

  app.use(express.json());
  app.use(log(logger));
  app.use(auth.initialize);
  app.use(api({config, db, auth}));
  app.use(catchErrors);

  return app;
};
