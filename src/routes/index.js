const {Router} = require('express');
const statistics = require('./statistics');

const router = Router();

router.use('/statistics', statistics);

module.exports = router;
