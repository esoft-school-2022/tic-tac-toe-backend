const {Router} = require('express');
const auth = require('./auth');
const statistics = require('./statistics');
const games = require('./games');
const users = require('./users');

module.exports = ({config, db, authMiddleware}) => {
  const router = Router();
  const authenticate = authMiddleware.authenticate('jwt', {session: false}, null);

  router.use('/auth', auth({config, db, authenticate}));
  router.use('/statistics', authenticate, statistics({db}));
  router.use('/games', authenticate, games({db}));
  router.use('/users', authenticate, users({db}));

  return router;
};
