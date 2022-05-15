const express = require('express');
const {catchErrors, auth} = require('./middlewares');
const api = require('./routes');

module.exports = ({config, db}) => {
  const app = express();
  const authMiddleware = auth({config, db});

  app.use(express.json());
  app.use(express.static('public', {index: false}));
  app.use(authMiddleware.initialize({}));
  app.use('/api', api({config, db, authMiddleware}));
  app.get(
    '*',
    (_, res) =>
      res.sendFile('index.html', {root: 'public'})
  );
  // app.use(catchErrors);

  return app;
};
