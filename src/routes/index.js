const {Router} = require('express');
const authRouter = require('./auth');
const statisticsRouter = require('./statistics');
const gamesRouter = require('./games');
const usersRouter = require('./users');

module.exports = ({config, db, auth, broker}) => {
  const router = Router();

  router.use('/auth', authRouter({config, db, auth, broker}));
  router.use('/statistics', auth.authenticate, statisticsRouter({db}));
  router.use('/games', auth.authenticate, gamesRouter({db}));
  router.use('/users', auth.authenticate, usersRouter({db}));

  return router;
};
