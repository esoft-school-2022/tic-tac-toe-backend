const express = require('express');
const {catchErrors, auth} = require('./middlewares');
const api = require('./routes');

module.exports = ({config, db}) => {
  const app = express();
  const authMiddleware = auth({config, db});

  app.use(express.json());
  app.use(authMiddleware.initialize({}));
  app.use('/api', api({config, db, authMiddleware}));
  app.use(catchErrors);

  return app;
};
