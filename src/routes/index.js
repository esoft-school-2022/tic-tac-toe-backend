const {Router} = require('express');
const statistics = require('./statistics');
const games = require('./games');

const router = Router();

router.use('/statistics', statistics);
router.use('/games', games);

module.exports = router;
