const {Router} = require('express');
const {auth: authMiddleware} = require('../middlewares');
const auth = require('./auth');
const statistics = require('./statistics');
const games = require('./games');
const users = require('./users');

const router = Router();
const authenticate = authMiddleware.authenticate('jwt', {session: false}, null);

router.use('/auth', auth);
router.use('/statistics', authenticate, statistics);
router.use('/games', authenticate, games);
router.use('/users', authenticate, users);

module.exports = router;
