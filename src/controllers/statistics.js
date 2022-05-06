const {getWinRateStatistics, getStatistics} = require('../services');
const {countPages} = require('../utils');

/**
 * Обрабатывает HTTP-запрос на получение статистики по игрокам.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @return {Promise<void>}
 */
const getWinRateStatisticsController = async(
  req,
  res
) => {
  const {withPageCount = false, order = 'desc'} = req.query;
  const limit = Number(req.query.limit) >= 0 ? Number(req.query.limit) : 10;
  const page = Number(req.query.page);
  const offset = Number(req.query.offset) || 0;
  const [statistics, pageCount] = await Promise.all([
    page ?
      getWinRateStatistics(limit, (page - 1) * limit, order) :
      getWinRateStatistics(limit, offset, order),
    ...withPageCount ?
      [countPages(limit, getStatistics())] :
      []
  ]);

  res.json({
    statistics,
    ...withPageCount ? pageCount : {}
  });
};

module.exports = {
  getWinRateStatisticsController
};
