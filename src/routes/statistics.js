const {Router} = require('express');
const {getWinRateStatisticsController} = require('../controllers');
const {catchPromise} = require('../utils/errorHandling');

const router = Router();

router.get('/', catchPromise(getWinRateStatisticsController));

module.exports = router;
