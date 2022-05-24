const {Controller} = require('../base');
const {StatisticsDAL} = require('../models');

class StatisticsController extends Controller {
  constructor({db}) {
    super();

    this.stats = new StatisticsDAL({db});
  }

  /**
   * Обрабатывает HTTP-запрос на получение статистики по игрокам.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @return {Promise<void>}
   */
  getWinRateStatistics = async(
    req,
    res
  ) => {
    const {withPageCount = false, order = 'desc'} = req.query;
    const limit = Number(req.query.limit) >= 0 ? Number(req.query.limit) : 10;
    const page = Number(req.query.page);
    const offset = Number(req.query.offset) || 0;
    const query = page ?
      this.stats.getWinRateStatistics(limit, (page - 1) * limit, order) :
      this.stats.getWinRateStatistics(limit, offset, order);
    const statistics = withPageCount ?
      await this.stats.withPages(limit)(query) :
      await query;

    res.json({
      statistics: statistics.map(({pageCount, ...rest}) => rest),
      ...withPageCount ? {pageCount: statistics[0]?.pageCount} : {}
    });
  }

  /**
   * Обрабатывает HTTP-запрос на получение статистики по игроку.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @return {Promise<void>}
   */
  getPlayerWinRateStatistics = async(
    req,
    res
  ) => {
    const {playerId} = req.params;

    res.json(await this.stats.getPlayerWinRateStatistics(playerId));
  }
}


module.exports = StatisticsController;
