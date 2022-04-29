const {Router} = require('express');
const {getWinRateStatisticsController} = require('../controllers');

const router = Router();

router.get('/', getWinRateStatisticsController)

module.exports = router;
