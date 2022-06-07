const express = require('express');
const {catchErrors} = require('./middlewares');
const api = require('./routes');

module.exports = ({config, db, auth}) => {
  const app = express();

  app.use(express.json());
  app.use(auth.initialize);
  app.use('/api', api({config, db, auth}));
  app.use(catchErrors);

  return app;
};
