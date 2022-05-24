const {Router} = require('express');
const {StatisticsController} = require('../controllers');
const {catchPromise} = require('../utils');

module.exports = ({db}) => {
  const router = Router();
  const stats = new StatisticsController({db});

  router.get('/', catchPromise(stats.getWinRateStatistics));
  router.get('/:playerId', catchPromise(stats.getPlayerWinRateStatistics));

  return router;
};
